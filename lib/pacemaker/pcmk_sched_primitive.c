/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/msg_xml.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

gboolean DeleteRsc(pe_resource_t *rsc, const pe_node_t *node, gboolean optional,
                   pe_working_set_t *data_set);
static bool StopRsc(pe_resource_t *rsc, pe_node_t *next, bool optional);
static bool StartRsc(pe_resource_t *rsc, pe_node_t *next, bool optional);
static bool DemoteRsc(pe_resource_t *rsc, pe_node_t *next, bool optional);
static bool PromoteRsc(pe_resource_t *rsc, pe_node_t *next, bool optional);
static bool RoleError(pe_resource_t *rsc, pe_node_t *next, bool optional);
static bool NullOp(pe_resource_t *rsc, pe_node_t *next, bool optional);

/* This array says what the *next* role should be when transitioning from one
 * role to another. For example going from Stopped to Promoted, the next role is
 * RSC_ROLE_UNPROMOTED, because the resource must be started before being promoted.
 * The current state then becomes Started, which is fed into this array again,
 * giving a next role of RSC_ROLE_PROMOTED.
 */
static enum rsc_role_e rsc_state_matrix[RSC_ROLE_MAX][RSC_ROLE_MAX] = {
/* Current state  Next state*/
/*                 Unknown           Stopped           Started           Unpromoted           Promoted */
/* Unknown */    { RSC_ROLE_UNKNOWN, RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_STOPPED,    RSC_ROLE_STOPPED },
/* Stopped */    { RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_STARTED, RSC_ROLE_UNPROMOTED, RSC_ROLE_UNPROMOTED },
/* Started */    { RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_STARTED, RSC_ROLE_UNPROMOTED, RSC_ROLE_PROMOTED },
/* Unpromoted */ { RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_UNPROMOTED, RSC_ROLE_PROMOTED },
/* Promoted  */  { RSC_ROLE_STOPPED, RSC_ROLE_UNPROMOTED, RSC_ROLE_UNPROMOTED, RSC_ROLE_UNPROMOTED, RSC_ROLE_PROMOTED },
};

typedef bool (*rsc_transition_fn)(pe_resource_t *rsc, pe_node_t *next,
                                  bool optional);

// This array picks the function needed to transition from one role to another
static rsc_transition_fn rsc_action_matrix[RSC_ROLE_MAX][RSC_ROLE_MAX] = {
/* Current state   Next state                                            */
/*                 Unknown    Stopped    Started    Unpromoted Promoted  */
/* Unknown */    { RoleError, StopRsc,   RoleError, RoleError, RoleError,    },
/* Stopped */    { RoleError, NullOp,    StartRsc,  StartRsc,  RoleError,    },
/* Started */    { RoleError, StopRsc,   NullOp,    NullOp,    PromoteRsc,   },
/* Unpromoted */ { RoleError, StopRsc,   StopRsc,   NullOp,    PromoteRsc,   },
/* Promoted  */  { RoleError, DemoteRsc, DemoteRsc, DemoteRsc, NullOp,       },
};

/*!
 * \internal
 * \brief Get a list of a resource's allowed nodes sorted by node weight
 *
 * \param[in] rsc  Resource to check
 *
 * \return List of allowed nodes sorted by node weight
 */
static GList *
sorted_allowed_nodes(const pe_resource_t *rsc)
{
    if (rsc->allowed_nodes != NULL) {
        GList *nodes = g_hash_table_get_values(rsc->allowed_nodes);

        if (nodes != NULL) {
            return pcmk__sort_nodes(nodes, pe__current_node(rsc));
        }
    }
    return NULL;
}

/*!
 * \internal
 * \brief Assign a resource to its best allowed node, if possible
 *
 * \param[in] rsc     Resource to choose a node for
 * \param[in] prefer  If not NULL, prefer this node when all else equal
 *
 * \return true if \p rsc could be assigned to a node, otherwise false
 */
static bool
assign_best_node(pe_resource_t *rsc, pe_node_t *prefer)
{
    GList *nodes = NULL;
    pe_node_t *chosen = NULL;
    pe_node_t *best = NULL;
    bool result = false;

    pcmk__ban_insufficient_capacity(rsc, &prefer);

    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        // We've already finished assignment of resources to nodes
        return rsc->allocated_to != NULL;
    }

    // Sort allowed nodes by weight
    nodes = sorted_allowed_nodes(rsc);
    if (nodes != NULL) {
        best = (pe_node_t *) nodes->data; // First node has best score
    }

    if ((prefer != NULL) && (nodes != NULL)) {
        // Get the allowed node version of prefer
        chosen = g_hash_table_lookup(rsc->allowed_nodes, prefer->details->id);

        if (chosen == NULL) {
            pe_rsc_trace(rsc, "Preferred node %s for %s was unknown",
                         pe__node_name(prefer), rsc->id);

        /* Favor the preferred node as long as its weight is at least as good as
         * the best allowed node's.
         *
         * An alternative would be to favor the preferred node even if the best
         * node is better, when the best node's weight is less than INFINITY.
         */
        } else if (chosen->weight < best->weight) {
            pe_rsc_trace(rsc, "Preferred node %s for %s was unsuitable",
                         pe__node_name(chosen), rsc->id);
            chosen = NULL;

        } else if (!pcmk__node_available(chosen, true, false)) {
            pe_rsc_trace(rsc, "Preferred node %s for %s was unavailable",
                         pe__node_name(chosen), rsc->id);
            chosen = NULL;

        } else {
            pe_rsc_trace(rsc,
                         "Chose preferred node %s for %s (ignoring %d candidates)",
                         pe__node_name(chosen), rsc->id, g_list_length(nodes));
        }
    }

    if ((chosen == NULL) && (best != NULL)) {
        /* Either there is no preferred node, or the preferred node is not
         * suitable, but another node is allowed to run the resource.
         */

        chosen = best;

        if (!pe_rsc_is_unique_clone(rsc->parent)
            && (chosen->weight > 0) // Zero not acceptable
            && pcmk__node_available(chosen, false, false)) {
            /* If the resource is already running on a node, prefer that node if
             * it is just as good as the chosen node.
             *
             * We don't do this for unique clone instances, because
             * distribute_children() has already assigned instances to their
             * running nodes when appropriate, and if we get here, we don't want
             * remaining unassigned instances to prefer a node that's already
             * running another instance.
             */
            pe_node_t *running = pe__current_node(rsc);

            if (running == NULL) {
                // Nothing to do

            } else if (!pcmk__node_available(running, true, false)) {
                pe_rsc_trace(rsc, "Current node for %s (%s) can't run resources",
                             rsc->id, pe__node_name(running));

            } else {
                int nodes_with_best_score = 1;

                for (GList *iter = nodes->next; iter; iter = iter->next) {
                    pe_node_t *allowed = (pe_node_t *) iter->data;

                    if (allowed->weight != chosen->weight) {
                        // The nodes are sorted by weight, so no more are equal
                        break;
                    }
                    if (allowed->details == running->details) {
                        // Scores are equal, so prefer the current node
                        chosen = allowed;
                    }
                    nodes_with_best_score++;
                }

                if (nodes_with_best_score > 1) {
                    do_crm_log(((chosen->weight >= INFINITY)? LOG_WARNING : LOG_INFO),
                               "Chose %s for %s from %d nodes with score %s",
                               pe__node_name(chosen), rsc->id,
                               nodes_with_best_score,
                               pcmk_readable_score(chosen->weight));
                }
            }
        }

        pe_rsc_trace(rsc, "Chose %s for %s from %d candidates",
                     pe__node_name(chosen), rsc->id, g_list_length(nodes));
    }

    result = pcmk__assign_primitive(rsc, chosen, false);
    g_list_free(nodes);
    return result;
}

/*!
 * \internal
 * \brief Apply a "this with" colocation to a node's allowed node scores
 *
 * \param[in] data       Colocation to apply
 * \param[in] user_data  Resource being assigned
 */
static void
apply_this_with(void *data, void *user_data)
{
    pcmk__colocation_t *colocation = (pcmk__colocation_t *) data;
    pe_resource_t *rsc = (pe_resource_t *) user_data;

    GHashTable *archive = NULL;
    pe_resource_t *other = colocation->primary;

    // In certain cases, we will need to revert the node scores
    if ((colocation->dependent_role >= RSC_ROLE_PROMOTED)
        || ((colocation->score < 0) && (colocation->score > -INFINITY))) {
        archive = pcmk__copy_node_table(rsc->allowed_nodes);
    }

    pe_rsc_trace(rsc,
                 "%s: Assigning colocation %s primary %s first"
                 "(score=%d role=%s)",
                 rsc->id, colocation->id, other->id,
                 colocation->score, role2text(colocation->dependent_role));
    other->cmds->assign(other, NULL);

    // Apply the colocation score to this resource's allowed node scores
    rsc->cmds->apply_coloc_score(rsc, other, colocation, true);
    if ((archive != NULL)
        && !pcmk__any_node_available(rsc->allowed_nodes)) {
        pe_rsc_info(rsc,
                    "%s: Reverting scores from colocation with %s "
                    "because no nodes allowed",
                    rsc->id, other->id);
        g_hash_table_destroy(rsc->allowed_nodes);
        rsc->allowed_nodes = archive;
        archive = NULL;
    }
    if (archive != NULL) {
        g_hash_table_destroy(archive);
    }
}

/*!
 * \internal
 * \brief Apply a "with this" colocation to a node's allowed node scores
 *
 * \param[in] data       Colocation to apply
 * \param[in] user_data  Resource being assigned
 */
static void
apply_with_this(void *data, void *user_data)
{
    pcmk__colocation_t *colocation = (pcmk__colocation_t *) data;
    pe_resource_t *rsc = (pe_resource_t *) user_data;

    pe_resource_t *other = colocation->dependent;
    const float factor = colocation->score / (float) INFINITY;

    if (!pcmk__colocation_has_influence(colocation, NULL)) {
        return;
    }
    pe_rsc_trace(rsc,
                 "%s: Incorporating attenuated %s assignment scores due "
                 "to colocation %s", rsc->id, other->id, colocation->id);
    other->cmds->add_colocated_node_scores(other, rsc->id,
                                           &rsc->allowed_nodes,
                                           colocation->node_attribute,
                                           factor, pcmk__coloc_select_active);
}

/*!
 * \internal
 * \brief Update a Pacemaker Remote node once its connection has been assigned
 *
 * \param[in] connection  Connection resource that has been assigned
 */
static void
remote_connection_assigned(pe_resource_t *connection)
{
    pe_node_t *remote_node = pe_find_node(connection->cluster->nodes,
                                          connection->id);

    CRM_CHECK(remote_node != NULL, return);

    if ((connection->allocated_to != NULL)
        && (connection->next_role != RSC_ROLE_STOPPED)) {

        crm_trace("Pacemaker Remote node %s will be online",
                  remote_node->details->id);
        remote_node->details->online = TRUE;
        if (remote_node->details->unseen) {
            // Avoid unnecessary fence, since we will attempt connection
            remote_node->details->unclean = FALSE;
        }

    } else {
        crm_trace("Pacemaker Remote node %s will be shut down "
                  "(%sassigned connection's next role is %s)",
                  remote_node->details->id,
                  ((connection->allocated_to == NULL)? "un" : ""),
                  role2text(connection->next_role));
        remote_node->details->shutdown = TRUE;
    }
}

/*!
 * \internal
 * \brief Assign a primitive resource to a node
 *
 * \param[in] rsc     Resource to assign to a node
 * \param[in] prefer  Node to prefer, if all else is equal
 *
 * \return Node that \p rsc is assigned to, if assigned entirely to one node
 */
pe_node_t *
pcmk__primitive_assign(pe_resource_t *rsc, pe_node_t *prefer)
{
    CRM_ASSERT(rsc != NULL);

    // Never assign a child without parent being assigned first
    if ((rsc->parent != NULL)
        && !pcmk_is_set(rsc->parent->flags, pe_rsc_allocating)) {
        pe_rsc_debug(rsc, "%s: Assigning parent %s first",
                     rsc->id, rsc->parent->id);
        rsc->parent->cmds->assign(rsc->parent, prefer);
    }

    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        return rsc->allocated_to; // Assignment has already been done
    }

    // Ensure we detect assignment loops
    if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        pe_rsc_debug(rsc, "Breaking assignment loop involving %s", rsc->id);
        return NULL;
    }
    pe__set_resource_flags(rsc, pe_rsc_allocating);

    pe__show_node_weights(true, rsc, "Pre-assignment", rsc->allowed_nodes,
                          rsc->cluster);

    g_list_foreach(rsc->rsc_cons, apply_this_with, rsc);
    pe__show_node_weights(true, rsc, "Post-this-with", rsc->allowed_nodes,
                          rsc->cluster);

    g_list_foreach(rsc->rsc_cons_lhs, apply_with_this, rsc);

    if (rsc->next_role == RSC_ROLE_STOPPED) {
        pe_rsc_trace(rsc,
                     "Banning %s from all nodes because it will be stopped",
                     rsc->id);
        resource_location(rsc, NULL, -INFINITY, XML_RSC_ATTR_TARGET_ROLE,
                          rsc->cluster);

    } else if ((rsc->next_role > rsc->role)
               && !pcmk_is_set(rsc->cluster->flags, pe_flag_have_quorum)
               && (rsc->cluster->no_quorum_policy == no_quorum_freeze)) {
        crm_notice("Resource %s cannot be elevated from %s to %s due to "
                   "no-quorum-policy=freeze",
                   rsc->id, role2text(rsc->role), role2text(rsc->next_role));
        pe__set_next_role(rsc, rsc->role, "no-quorum-policy=freeze");
    }

    pe__show_node_weights(!pcmk_is_set(rsc->cluster->flags, pe_flag_show_scores),
                          rsc, __func__, rsc->allowed_nodes, rsc->cluster);

    // Unmanage resource if fencing is enabled but no device is configured
    if (pcmk_is_set(rsc->cluster->flags, pe_flag_stonith_enabled)
        && !pcmk_is_set(rsc->cluster->flags, pe_flag_have_stonith_resource)) {
        pe__clear_resource_flags(rsc, pe_rsc_managed);
    }

    if (!pcmk_is_set(rsc->flags, pe_rsc_managed)) {
        // Unmanaged resources stay on their current node
        const char *reason = NULL;
        pe_node_t *assign_to = NULL;

        pe__set_next_role(rsc, rsc->role, "unmanaged");
        assign_to = pe__current_node(rsc);
        if (assign_to == NULL) {
            reason = "inactive";
        } else if (rsc->role == RSC_ROLE_PROMOTED) {
            reason = "promoted";
        } else if (pcmk_is_set(rsc->flags, pe_rsc_failed)) {
            reason = "failed";
        } else {
            reason = "active";
        }
        pe_rsc_info(rsc, "Unmanaged resource %s assigned to %s: %s", rsc->id,
                    (assign_to? assign_to->details->uname : "no node"), reason);
        pcmk__assign_primitive(rsc, assign_to, true);

    } else if (pcmk_is_set(rsc->cluster->flags, pe_flag_stop_everything)) {
        pe_rsc_debug(rsc, "Forcing %s to stop: stop-all-resources", rsc->id);
        pcmk__assign_primitive(rsc, NULL, true);

    } else if (pcmk_is_set(rsc->flags, pe_rsc_provisional)
               && assign_best_node(rsc, prefer)) {
        // Assignment successful

    } else if (rsc->allocated_to == NULL) {
        if (!pcmk_is_set(rsc->flags, pe_rsc_orphan)) {
            pe_rsc_info(rsc, "Resource %s cannot run anywhere", rsc->id);
        } else if (rsc->running_on != NULL) {
            pe_rsc_info(rsc, "Stopping orphan resource %s", rsc->id);
        }

    } else {
        pe_rsc_debug(rsc, "%s: pre-assigned to %s", rsc->id,
                     pe__node_name(rsc->allocated_to));
    }

    pe__clear_resource_flags(rsc, pe_rsc_allocating);

    if (rsc->is_remote_node) {
        remote_connection_assigned(rsc);
    }

    return rsc->allocated_to;
}

/*!
 * \internal
 * \brief Schedule actions to bring resource down and back to current role
 *
 * \param[in] rsc           Resource to restart
 * \param[in] current       Node that resource should be brought down on
 * \param[in] chosen        Node that resource should be brought up on
 * \param[in] need_stop     Whether the resource must be stopped
 * \param[in] need_promote  Whether the resource must be promoted
 *
 * \return Role that resource would have after scheduled actions are taken
 */
static void
schedule_restart_actions(pe_resource_t *rsc, pe_node_t *current,
                         pe_node_t *chosen, bool need_stop, bool need_promote)
{
    enum rsc_role_e role = rsc->role;
    enum rsc_role_e next_role;

    pe__set_resource_flags(rsc, pe_rsc_restarting);

    // Bring resource down to a stop on its current node
    while (role != RSC_ROLE_STOPPED) {
        next_role = rsc_state_matrix[role][RSC_ROLE_STOPPED];
        pe_rsc_trace(rsc, "Creating %s action to take %s down from %s to %s",
                     (need_stop? "required" : "optional"), rsc->id,
                     role2text(role), role2text(next_role));
        if (!rsc_action_matrix[role][next_role](rsc, current, !need_stop)) {
            break;
        }
        role = next_role;
    }

    // Bring resource up to its next role on its next node
    while ((rsc->role <= rsc->next_role) && (role != rsc->role)
           && !pcmk_is_set(rsc->flags, pe_rsc_block)) {
        bool required = need_stop;

        next_role = rsc_state_matrix[role][rsc->role];
        if ((next_role == RSC_ROLE_PROMOTED) && need_promote) {
            required = true;
        }
        pe_rsc_trace(rsc, "Creating %s action to take %s up from %s to %s",
                     (required? "required" : "optional"), rsc->id,
                     role2text(role), role2text(next_role));
        if (!rsc_action_matrix[role][next_role](rsc, chosen, !required)) {
            break;
        }
        role = next_role;
    }

    pe__clear_resource_flags(rsc, pe_rsc_restarting);
}

/*!
 * \internal
 * \brief If a resource's next role is not explicitly specified, set a default
 *
 * \param[in,out] rsc  Resource to set next role for
 *
 * \return "explicit" if next role was explicitly set, otherwise "implicit"
 */
static const char *
set_default_next_role(pe_resource_t *rsc)
{
    if (rsc->next_role != RSC_ROLE_UNKNOWN) {
        return "explicit";
    }

    if (rsc->allocated_to == NULL) {
        pe__set_next_role(rsc, RSC_ROLE_STOPPED, "assignment");
    } else {
        pe__set_next_role(rsc, RSC_ROLE_STARTED, "assignment");
    }
    return "implicit";
}

/*!
 * \internal
 * \brief Create an action to represent an already pending start
 *
 * \param[in,out] rsc  Resource to create start action for
 */
static void
create_pending_start(pe_resource_t *rsc)
{
    pe_action_t *start = NULL;

    pe_rsc_trace(rsc,
                 "Creating action for %s to represent already pending start",
                 rsc->id);
    start = start_action(rsc, rsc->allocated_to, TRUE);
    pe__set_action_flags(start, pe_action_print_always);
}

/*!
 * \internal
 * \brief Schedule actions needed to take a resource to its next role
 *
 * \param[in,out] rsc  Resource to schedule actions for
 */
static void
schedule_role_transition_actions(pe_resource_t *rsc)
{
    enum rsc_role_e role = rsc->role;

    while (role != rsc->next_role) {
        enum rsc_role_e next_role = rsc_state_matrix[role][rsc->next_role];

        pe_rsc_trace(rsc,
                     "Creating action to take %s from %s to %s (ending at %s)",
                     rsc->id, role2text(role), role2text(next_role),
                     role2text(rsc->next_role));
        if (!rsc_action_matrix[role][next_role](rsc, rsc->allocated_to,
                                                false)) {
            break;
        }
        role = next_role;
    }
}

/*!
 * \internal
 * \brief Create all actions needed for a given primitive resource
 *
 * \param[in,out] rsc  Primitive resource to create actions for
 */
void
pcmk__primitive_create_actions(pe_resource_t *rsc)
{
    bool need_stop = false;
    bool need_promote = false;
    bool is_moving = false;
    bool allow_migrate = false;
    bool multiply_active = false;

    pe_node_t *current = NULL;
    unsigned int num_all_active = 0;
    unsigned int num_clean_active = 0;
    const char *next_role_source = NULL;

    CRM_ASSERT(rsc != NULL);

    next_role_source = set_default_next_role(rsc);
    pe_rsc_trace(rsc,
                 "Creating all actions for %s transition from %s to %s "
                 "(%s) on %s",
                 rsc->id, role2text(rsc->role), role2text(rsc->next_role),
                 next_role_source, pe__node_name(rsc->allocated_to));

    current = pe__find_active_on(rsc, &num_all_active, &num_clean_active);

    g_list_foreach(rsc->dangling_migrations, pcmk__abort_dangling_migration,
                   rsc);

    if ((current != NULL) && (rsc->allocated_to != NULL)
        && (current->details != rsc->allocated_to->details)
        && (rsc->next_role >= RSC_ROLE_STARTED)) {

        pe_rsc_trace(rsc, "Moving %s from %s to %s",
                     rsc->id, pe__node_name(current),
                     pe__node_name(rsc->allocated_to));
        is_moving = true;
        allow_migrate = pcmk__rsc_can_migrate(rsc, current);

        // This is needed even if migrating (though I'm not sure why ...)
        need_stop = true;
    }

    // Check whether resource is partially migrated and/or multiply active
    if ((rsc->partial_migration_source != NULL)
        && (rsc->partial_migration_target != NULL)
        && allow_migrate && (num_all_active == 2)
        && (current->details == rsc->partial_migration_source->details)
        && (rsc->allocated_to->details == rsc->partial_migration_target->details)) {
        /* A partial migration is in progress, and the migration target remains
         * the same as when the migration began.
         */
        pe_rsc_trace(rsc, "Partial migration of %s from %s to %s will continue",
                     rsc->id, pe__node_name(rsc->partial_migration_source),
                     pe__node_name(rsc->partial_migration_target));

    } else if ((rsc->partial_migration_source != NULL)
               || (rsc->partial_migration_target != NULL)) {
        // A partial migration is in progress but can't be continued

        if (num_all_active > 2) {
            // The resource is migrating *and* multiply active!
            crm_notice("Forcing recovery of %s because it is migrating "
                       "from %s to %s and possibly active elsewhere",
                       rsc->id, pe__node_name(rsc->partial_migration_source),
                       pe__node_name(rsc->partial_migration_target));
        } else {
            // The migration source or target isn't available
            crm_notice("Forcing recovery of %s because it can no longer "
                       "migrate from %s to %s",
                       rsc->id, pe__node_name(rsc->partial_migration_source),
                       pe__node_name(rsc->partial_migration_target));
        }
        need_stop = true;
        rsc->partial_migration_source = rsc->partial_migration_target = NULL;
        allow_migrate = false;

    } else if (pcmk_is_set(rsc->flags, pe_rsc_needs_fencing)) {
        multiply_active = (num_all_active > 1);
    } else {
        /* If a resource has "requires" set to nothing or quorum, don't consider
         * it active on unclean nodes (similar to how all resources behave when
         * stonith-enabled is false). We can start such resources elsewhere
         * before fencing completes, and if we considered the resource active on
         * the failed node, we would attempt recovery for being active on
         * multiple nodes.
         */
        multiply_active = (num_clean_active > 1);
    }

    if (multiply_active) {
        const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);

        // Resource was (possibly) incorrectly multiply active
        pe_proc_err("%s resource %s might be active on %u nodes (%s)",
                    pcmk__s(class, "Untyped"), rsc->id, num_all_active,
                    recovery2text(rsc->recovery_type));
        crm_notice("See https://wiki.clusterlabs.org/wiki/FAQ"
                   "#Resource_is_Too_Active for more information");

        switch (rsc->recovery_type) {
            case recovery_stop_start:
                need_stop = true;
                break;
            case recovery_stop_unexpected:
                need_stop = true; // StopRsc() will skip expected node
                pe__set_resource_flags(rsc, pe_rsc_stop_unexpected);
                break;
            default:
                break;
        }

    } else {
        pe__clear_resource_flags(rsc, pe_rsc_stop_unexpected);
    }

    if (pcmk_is_set(rsc->flags, pe_rsc_start_pending)) {
        create_pending_start(rsc);
    }

    if (is_moving) {
        // Remaining tests are only for resources staying where they are

    } else if (pcmk_is_set(rsc->flags, pe_rsc_failed)) {
        if (pcmk_is_set(rsc->flags, pe_rsc_stop)) {
            need_stop = true;
            pe_rsc_trace(rsc, "Recovering %s", rsc->id);
        } else {
            pe_rsc_trace(rsc, "Recovering %s by demotion", rsc->id);
            if (rsc->next_role == RSC_ROLE_PROMOTED) {
                need_promote = true;
            }
        }

    } else if (pcmk_is_set(rsc->flags, pe_rsc_block)) {
        pe_rsc_trace(rsc, "Blocking further actions on %s", rsc->id);
        need_stop = true;

    } else if ((rsc->role > RSC_ROLE_STARTED) && (current != NULL)
               && (rsc->allocated_to != NULL)) {
        pe_action_t *start = NULL;

        pe_rsc_trace(rsc, "Creating start action for promoted resource %s",
                     rsc->id);
        start = start_action(rsc, rsc->allocated_to, TRUE);
        if (!pcmk_is_set(start->flags, pe_action_optional)) {
            // Recovery of a promoted resource
            pe_rsc_trace(rsc, "%s restart is required for recovery", rsc->id);
            need_stop = true;
        }
    }

    // Create any actions needed to bring resource down and back up to same role
    schedule_restart_actions(rsc, current, rsc->allocated_to, need_stop,
                             need_promote);

    // Create any actions needed to take resource from this role to the next
    schedule_role_transition_actions(rsc);

    pcmk__create_recurring_actions(rsc);

    if (allow_migrate) {
        pcmk__create_migration_actions(rsc, current);
    }
}

/*!
 * \internal
 * \brief Ban a resource from any allowed nodes that are Pacemaker Remote nodes
 *
 * \param[in] rsc  Resource to check
 */
static void
rsc_avoids_remote_nodes(const pe_resource_t *rsc)
{
    GHashTableIter iter;
    pe_node_t *node = NULL;

    g_hash_table_iter_init(&iter, rsc->allowed_nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **) &node)) {
        if (node->details->remote_rsc != NULL) {
            node->weight = -INFINITY;
        }
    }
}

/*!
 * \internal
 * \brief Return allowed nodes as (possibly sorted) list
 *
 * Convert a resource's hash table of allowed nodes to a list. If printing to
 * stdout, sort the list, to keep action ID numbers consistent for regression
 * test output (while avoiding the performance hit on a live cluster).
 *
 * \param[in] rsc       Resource to check for allowed nodes
 * \param[in] data_set  Cluster working set
 *
 * \return List of resource's allowed nodes
 * \note Callers should take care not to rely on the list being sorted.
 */
static GList *
allowed_nodes_as_list(pe_resource_t *rsc, pe_working_set_t *data_set)
{
    GList *allowed_nodes = NULL;

    if (rsc->allowed_nodes) {
        allowed_nodes = g_hash_table_get_values(rsc->allowed_nodes);
    }

    if (!pcmk__is_daemon) {
        allowed_nodes = g_list_sort(allowed_nodes, pe__cmp_node_name);
    }

    return allowed_nodes;
}

/*!
 * \internal
 * \brief Create implicit constraints needed for a primitive resource
 *
 * \param[in,out] rsc  Primitive resource to create implicit constraints for
 */
void
pcmk__primitive_internal_constraints(pe_resource_t *rsc)
{
    pe_resource_t *top = NULL;
    GList *allowed_nodes = NULL;
    bool check_unfencing = false;
    bool check_utilization = false;

    CRM_ASSERT(rsc != NULL);

    if (!pcmk_is_set(rsc->flags, pe_rsc_managed)) {
        pe_rsc_trace(rsc,
                     "Skipping implicit constraints for unmanaged resource %s",
                     rsc->id);
        return;
    }

    top = uber_parent(rsc);

    // Whether resource requires unfencing
    check_unfencing = !pcmk_is_set(rsc->flags, pe_rsc_fence_device)
                      && pcmk_is_set(rsc->cluster->flags, pe_flag_enable_unfencing)
                      && pcmk_is_set(rsc->flags, pe_rsc_needs_unfencing);

    // Whether a non-default placement strategy is used
    check_utilization = (g_hash_table_size(rsc->utilization) > 0)
                         && !pcmk__str_eq(rsc->cluster->placement_strategy,
                                          "default", pcmk__str_casei);

    // Order stops before starts (i.e. restart)
    pcmk__new_ordering(rsc, pcmk__op_key(rsc->id, RSC_STOP, 0), NULL,
                       rsc, pcmk__op_key(rsc->id, RSC_START, 0), NULL,
                       pe_order_optional|pe_order_implies_then|pe_order_restart,
                       rsc->cluster);

    // Promotable ordering: demote before stop, start before promote
    if (pcmk_is_set(top->flags, pe_rsc_promotable)
        || (rsc->role > RSC_ROLE_UNPROMOTED)) {

        pcmk__new_ordering(rsc, pcmk__op_key(rsc->id, RSC_DEMOTE, 0), NULL,
                           rsc, pcmk__op_key(rsc->id, RSC_STOP, 0), NULL,
                           pe_order_promoted_implies_first, rsc->cluster);

        pcmk__new_ordering(rsc, pcmk__op_key(rsc->id, RSC_START, 0), NULL,
                           rsc, pcmk__op_key(rsc->id, RSC_PROMOTE, 0), NULL,
                           pe_order_runnable_left, rsc->cluster);
    }

    // Don't clear resource history if probing on same node
    pcmk__new_ordering(rsc, pcmk__op_key(rsc->id, CRM_OP_LRM_DELETE, 0),
                       NULL, rsc, pcmk__op_key(rsc->id, RSC_STATUS, 0),
                       NULL, pe_order_same_node|pe_order_then_cancels_first,
                       rsc->cluster);

    // Certain checks need allowed nodes
    if (check_unfencing || check_utilization || (rsc->container != NULL)) {
        allowed_nodes = allowed_nodes_as_list(rsc, rsc->cluster);
    }

    if (check_unfencing) {
        // Check whether the node needs to be unfenced

        for (GList *item = allowed_nodes; item; item = item->next) {
            pe_node_t *node = item->data;
            pe_action_t *unfence = pe_fence_op(node, "on", TRUE, NULL, FALSE,
                                               rsc->cluster);

            crm_debug("Ordering any stops of %s before %s, and any starts after",
                      rsc->id, unfence->uuid);

            /*
             * It would be more efficient to order clone resources once,
             * rather than order each instance, but ordering the instance
             * allows us to avoid unnecessary dependencies that might conflict
             * with user constraints.
             *
             * @TODO: This constraint can still produce a transition loop if the
             * resource has a stop scheduled on the node being unfenced, and
             * there is a user ordering constraint to start some other resource
             * (which will be ordered after the unfence) before stopping this
             * resource. An example is "start some slow-starting cloned service
             * before stopping an associated virtual IP that may be moving to
             * it":
             *       stop this -> unfencing -> start that -> stop this
             */
            pcmk__new_ordering(rsc, stop_key(rsc), NULL,
                               NULL, strdup(unfence->uuid), unfence,
                               pe_order_optional|pe_order_same_node,
                               rsc->cluster);

            pcmk__new_ordering(NULL, strdup(unfence->uuid), unfence,
                               rsc, start_key(rsc), NULL,
                               pe_order_implies_then_on_node|pe_order_same_node,
                               rsc->cluster);
        }
    }

    if (check_utilization) {
        pcmk__create_utilization_constraints(rsc, allowed_nodes);
    }

    if (rsc->container != NULL) {
        pe_resource_t *remote_rsc = NULL;

        if (rsc->is_remote_node) {
            // rsc is the implicit remote connection for a guest or bundle node

            /* Guest resources are not allowed to run on Pacemaker Remote nodes,
             * to avoid nesting remotes. However, bundles are allowed.
             */
            if (!pcmk_is_set(rsc->flags, pe_rsc_allow_remote_remotes)) {
                rsc_avoids_remote_nodes(rsc->container);
            }

            /* If someone cleans up a guest or bundle node's container, we will
             * likely schedule a (re-)probe of the container and recovery of the
             * connection. Order the connection stop after the container probe,
             * so that if we detect the container running, we will trigger a new
             * transition and avoid the unnecessary recovery.
             */
            pcmk__order_resource_actions(rsc->container, RSC_STATUS, rsc,
                                         RSC_STOP, pe_order_optional);

        /* A user can specify that a resource must start on a Pacemaker Remote
         * node by explicitly configuring it with the container=NODENAME
         * meta-attribute. This is of questionable merit, since location
         * constraints can accomplish the same thing. But we support it, so here
         * we check whether a resource (that is not itself a remote connection)
         * has container set to a remote node or guest node resource.
         */
        } else if (rsc->container->is_remote_node) {
            remote_rsc = rsc->container;
        } else  {
            remote_rsc = pe__resource_contains_guest_node(rsc->cluster,
                                                          rsc->container);
        }

        if (remote_rsc != NULL) {
            /* Force the resource on the Pacemaker Remote node instead of
             * colocating the resource with the container resource.
             */
            for (GList *item = allowed_nodes; item; item = item->next) {
                pe_node_t *node = item->data;

                if (node->details->remote_rsc != remote_rsc) {
                    node->weight = -INFINITY;
                }
            }

        } else {
            /* This resource is either a filler for a container that does NOT
             * represent a Pacemaker Remote node, or a Pacemaker Remote
             * connection resource for a guest node or bundle.
             */
            int score;

            crm_trace("Order and colocate %s relative to its container %s",
                      rsc->id, rsc->container->id);

            pcmk__new_ordering(rsc->container,
                               pcmk__op_key(rsc->container->id, RSC_START, 0),
                               NULL, rsc, pcmk__op_key(rsc->id, RSC_START, 0),
                               NULL,
                               pe_order_implies_then|pe_order_runnable_left,
                               rsc->cluster);

            pcmk__new_ordering(rsc, pcmk__op_key(rsc->id, RSC_STOP, 0), NULL,
                               rsc->container,
                               pcmk__op_key(rsc->container->id, RSC_STOP, 0),
                               NULL, pe_order_implies_first, rsc->cluster);

            if (pcmk_is_set(rsc->flags, pe_rsc_allow_remote_remotes)) {
                score = 10000;    /* Highly preferred but not essential */
            } else {
                score = INFINITY; /* Force them to run on the same host */
            }
            pcmk__new_colocation("resource-with-container", NULL, score, rsc,
                                 rsc->container, NULL, NULL, true,
                                 rsc->cluster);
        }
    }

    if (rsc->is_remote_node || pcmk_is_set(rsc->flags, pe_rsc_fence_device)) {
        /* Remote connections and fencing devices are not allowed to run on
         * Pacemaker Remote nodes
         */
        rsc_avoids_remote_nodes(rsc);
    }
    g_list_free(allowed_nodes);
}

/*!
 * \internal
 * \brief Apply a colocation's score to node weights or resource priority
 *
 * Given a colocation constraint, apply its score to the dependent's
 * allowed node weights (if we are still placing resources) or priority (if
 * we are choosing promotable clone instance roles).
 *
 * \param[in] dependent      Dependent resource in colocation
 * \param[in] primary        Primary resource in colocation
 * \param[in] colocation     Colocation constraint to apply
 * \param[in] for_dependent  true if called on behalf of dependent
 */
void
pcmk__primitive_apply_coloc_score(pe_resource_t *dependent,
                                  pe_resource_t *primary,
                                  pcmk__colocation_t *colocation,
                                  bool for_dependent)
{
    enum pcmk__coloc_affects filter_results;

    CRM_CHECK((colocation != NULL) && (dependent != NULL) && (primary != NULL),
              return);

    if (for_dependent) {
        // Always process on behalf of primary resource
        primary->cmds->apply_coloc_score(dependent, primary, colocation, false);
        return;
    }

    filter_results = pcmk__colocation_affects(dependent, primary, colocation,
                                              false);
    pe_rsc_trace(dependent, "%s %s with %s (%s, score=%d, filter=%d)",
                 ((colocation->score > 0)? "Colocating" : "Anti-colocating"),
                 dependent->id, primary->id, colocation->id, colocation->score,
                 filter_results);

    switch (filter_results) {
        case pcmk__coloc_affects_role:
            pcmk__apply_coloc_to_priority(dependent, primary, colocation);
            break;
        case pcmk__coloc_affects_location:
            pcmk__apply_coloc_to_weights(dependent, primary, colocation);
            break;
        default: // pcmk__coloc_affects_nothing
            return;
    }
}

/*!
 * \internal
 * \brief Return action flags for a given primitive resource action
 *
 * \param[in,out] action  Action to get flags for
 * \param[in]     node    If not NULL, limit effects to this node
 *
 * \return Flags appropriate to \p action on \p node
 */
enum pe_action_flags
pcmk__primitive_action_flags(pe_action_t *action, const pe_node_t *node)
{
    CRM_ASSERT(action != NULL);
    return action->flags;
}

void
native_rsc_location(pe_resource_t *rsc, pe__location_t *constraint)
{
    pcmk__apply_location(rsc, constraint);
}

/*!
 * \internal
 * \brief Check whether a node is a multiply active resource's expected node
 *
 * \param[in] rsc  Resource to check
 * \param[in] node  Node to check
 *
 * \return true if \p rsc is multiply active with multiple-active set to
 *         stop_unexpected, and \p node is the node where it will remain active
 * \note This assumes that the resource's next role cannot be changed to stopped
 *       after this is called, which should be reasonable if status has already
 *       been unpacked and resources have been assigned to nodes.
 */
static bool
is_expected_node(const pe_resource_t *rsc, const pe_node_t *node)
{
    return pcmk_all_flags_set(rsc->flags,
                              pe_rsc_stop_unexpected|pe_rsc_restarting)
           && (rsc->next_role > RSC_ROLE_STOPPED)
           && (rsc->allocated_to != NULL) && (node != NULL)
           && (rsc->allocated_to->details == node->details);
}

static bool
StopRsc(pe_resource_t *rsc, pe_node_t *next, bool optional)
{
    GList *gIter = NULL;

    CRM_ASSERT(rsc);

    for (gIter = rsc->running_on; gIter != NULL; gIter = gIter->next) {
        pe_node_t *current = (pe_node_t *) gIter->data;
        pe_action_t *stop;

        if (is_expected_node(rsc, current)) {
            /* We are scheduling restart actions for a multiply active resource
             * with multiple-active=stop_unexpected, and this is where it should
             * not be stopped.
             */
            pe_rsc_trace(rsc,
                         "Skipping stop of multiply active resource %s "
                         "on expected node %s",
                         rsc->id, pe__node_name(current));
            continue;
        }

        if (rsc->partial_migration_target) {
            if (rsc->partial_migration_target->details == current->details
                // Only if the allocated node still is the migration target.
                && rsc->allocated_to
                && rsc->allocated_to->details == rsc->partial_migration_target->details) {
                pe_rsc_trace(rsc,
                             "Skipping stop of %s on %s "
                             "because migration to %s in progress",
                             rsc->id, pe__node_name(current),
                             pe__node_name(next));
                continue;
            } else {
                pe_rsc_trace(rsc,
                             "Forcing stop of %s on %s "
                             "because migration target changed",
                             rsc->id, pe__node_name(current));
                optional = false;
            }
        }

        pe_rsc_trace(rsc, "Scheduling stop of %s on %s",
                     rsc->id, pe__node_name(current));
        stop = stop_action(rsc, current, optional);

        if(rsc->allocated_to == NULL) {
            pe_action_set_reason(stop, "node availability", TRUE);
        } else if (pcmk_all_flags_set(rsc->flags, pe_rsc_restarting
                                                  |pe_rsc_stop_unexpected)) {
            /* We are stopping a multiply active resource on a node that is
             * not its expected node, and we are still scheduling restart
             * actions, so the stop is for being multiply active.
             */
            pe_action_set_reason(stop, "being multiply active", TRUE);
        }

        if (!pcmk_is_set(rsc->flags, pe_rsc_managed)) {
            pe__clear_action_flags(stop, pe_action_runnable);
        }

        if (pcmk_is_set(rsc->cluster->flags, pe_flag_remove_after_stop)) {
            DeleteRsc(rsc, current, optional, rsc->cluster);
        }

        if (pcmk_is_set(rsc->flags, pe_rsc_needs_unfencing)) {
            pe_action_t *unfence = pe_fence_op(current, "on", TRUE, NULL, FALSE,
                                               rsc->cluster);

            order_actions(stop, unfence, pe_order_implies_first);
            if (!pcmk__node_unfenced(current)) {
                pe_proc_err("Stopping %s until %s can be unfenced",
                            rsc->id, pe__node_name(current));
            }
        }
    }

    return true;
}

static bool
StartRsc(pe_resource_t *rsc, pe_node_t *next, bool optional)
{
    pe_action_t *start = NULL;

    CRM_ASSERT(rsc);

    pe_rsc_trace(rsc, "Scheduling %s start of %s on %s (weight=%d)",
                 (optional? "optional" : "required"), rsc->id,
                 pe__node_name(next),
                 ((next == NULL)? 0 : next->weight));
    start = start_action(rsc, next, TRUE);

    pcmk__order_vs_unfence(rsc, next, start, pe_order_implies_then);

    if (pcmk_is_set(start->flags, pe_action_runnable) && !optional) {
        pe__clear_action_flags(start, pe_action_optional);
    }

    if (is_expected_node(rsc, next)) {
        /* This could be a problem if the start becomes necessary for other
         * reasons later.
         */
        pe_rsc_trace(rsc,
                     "Start of multiply active resouce %s "
                     "on expected node %s will be a pseudo-action",
                     rsc->id, pe__node_name(next));
        pe__set_action_flags(start, pe_action_pseudo);
    }

    return true;
}

static bool
PromoteRsc(pe_resource_t *rsc, pe_node_t *next, bool optional)
{
    GList *gIter = NULL;
    gboolean runnable = TRUE;
    GList *action_list = NULL;

    CRM_ASSERT(rsc);
    CRM_CHECK(next != NULL, return false);

    pe_rsc_trace(rsc, "%s on %s", rsc->id, pe__node_name(next));

    action_list = pe__resource_actions(rsc, next, RSC_START, TRUE);

    for (gIter = action_list; gIter != NULL; gIter = gIter->next) {
        pe_action_t *start = (pe_action_t *) gIter->data;

        if (!pcmk_is_set(start->flags, pe_action_runnable)) {
            runnable = FALSE;
        }
    }
    g_list_free(action_list);

    if (runnable) {
        pe_action_t *promote = promote_action(rsc, next, optional);

        if (is_expected_node(rsc, next)) {
            /* This could be a problem if the promote becomes necessary for
             * other reasons later.
             */
            pe_rsc_trace(rsc,
                         "Promotion of multiply active resouce %s "
                         "on expected node %s will be a pseudo-action",
                         rsc->id, pe__node_name(next));
            pe__set_action_flags(promote, pe_action_pseudo);
        }

        return true;
    }

    pe_rsc_debug(rsc, "%s\tPromote %s (canceled)",
                 pe__node_name(next), rsc->id);

    action_list = pe__resource_actions(rsc, next, RSC_PROMOTE, TRUE);

    for (gIter = action_list; gIter != NULL; gIter = gIter->next) {
        pe_action_t *promote = (pe_action_t *) gIter->data;

        pe__clear_action_flags(promote, pe_action_runnable);
    }

    g_list_free(action_list);
    return true;
}

static bool
DemoteRsc(pe_resource_t *rsc, pe_node_t *next, bool optional)
{
    GList *gIter = NULL;

    CRM_ASSERT(rsc);

    if (is_expected_node(rsc, next)) {
        pe_rsc_trace(rsc,
                     "Skipping demote of multiply active resource %s "
                     "on expected node %s",
                     rsc->id, pe__node_name(next));
        return true;
    }

    pe_rsc_trace(rsc, "%s", rsc->id);

    /* CRM_CHECK(rsc->next_role == RSC_ROLE_UNPROMOTED, return FALSE); */
    for (gIter = rsc->running_on; gIter != NULL; gIter = gIter->next) {
        pe_node_t *current = (pe_node_t *) gIter->data;

        pe_rsc_trace(rsc, "%s on %s", rsc->id, pe__node_name(next));
        demote_action(rsc, current, optional);
    }
    return true;
}

static bool
RoleError(pe_resource_t *rsc, pe_node_t *next, bool optional)
{
    CRM_ASSERT(rsc);
    crm_err("%s on %s", rsc->id, pe__node_name(next));
    CRM_CHECK(false, return false);
    return false;
}

static bool
NullOp(pe_resource_t *rsc, pe_node_t *next, bool optional)
{
    CRM_ASSERT(rsc);
    pe_rsc_trace(rsc, "%s", rsc->id);
    return FALSE;
}

gboolean
DeleteRsc(pe_resource_t *rsc, const pe_node_t *node, gboolean optional,
          pe_working_set_t *data_set)
{
    if (pcmk_is_set(rsc->flags, pe_rsc_failed)) {
        pe_rsc_trace(rsc, "Resource %s not deleted from %s: failed",
                     rsc->id, pe__node_name(node));
        return FALSE;

    } else if (node == NULL) {
        pe_rsc_trace(rsc, "Resource %s not deleted: NULL node", rsc->id);
        return FALSE;

    } else if (node->details->unclean || node->details->online == FALSE) {
        pe_rsc_trace(rsc, "Resource %s not deleted from %s: unrunnable",
                     rsc->id, pe__node_name(node));
        return FALSE;
    }

    crm_notice("Removing %s from %s", rsc->id, pe__node_name(node));

    delete_action(rsc, node, optional);

    pcmk__order_resource_actions(rsc, RSC_STOP, rsc, RSC_DELETE,
                                 optional? pe_order_implies_then : pe_order_optional);

    pcmk__order_resource_actions(rsc, RSC_DELETE, rsc, RSC_START,
                                 optional? pe_order_implies_then : pe_order_optional);

    return TRUE;
}

void
native_append_meta(pe_resource_t * rsc, xmlNode * xml)
{
    char *value = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_INCARNATION);
    pe_resource_t *parent;

    if (value) {
        char *name = NULL;

        name = crm_meta_name(XML_RSC_ATTR_INCARNATION);
        crm_xml_add(xml, name, value);
        free(name);
    }

    value = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_REMOTE_NODE);
    if (value) {
        char *name = NULL;

        name = crm_meta_name(XML_RSC_ATTR_REMOTE_NODE);
        crm_xml_add(xml, name, value);
        free(name);
    }

    for (parent = rsc; parent != NULL; parent = parent->parent) {
        if (parent->container) {
            crm_xml_add(xml, CRM_META"_"XML_RSC_ATTR_CONTAINER, parent->container->id);
        }
    }
}

// Primitive implementation of resource_alloc_functions_t:add_utilization()
void
pcmk__primitive_add_utilization(pe_resource_t *rsc, pe_resource_t *orig_rsc,
                                GList *all_rscs, GHashTable *utilization)
{
    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        return;
    }

    pe_rsc_trace(orig_rsc, "%s: Adding primitive %s as colocated utilization",
                 orig_rsc->id, rsc->id);
    pcmk__release_node_capacity(utilization, rsc);
}

/*!
 * \internal
 * \brief Get epoch time of node's shutdown attribute (or now if none)
 *
 * \param[in] node      Node to check
 * \param[in] data_set  Cluster working set
 *
 * \return Epoch time corresponding to shutdown attribute if set or now if not
 */
static time_t
shutdown_time(pe_node_t *node, pe_working_set_t *data_set)
{
    const char *shutdown = pe_node_attribute_raw(node, XML_CIB_ATTR_SHUTDOWN);
    time_t result = 0;

    if (shutdown != NULL) {
        long long result_ll;

        if (pcmk__scan_ll(shutdown, &result_ll, 0LL) == pcmk_rc_ok) {
            result = (time_t) result_ll;
        }
    }
    return (result == 0)? get_effective_time(data_set) : result;
}

// Primitive implementation of resource_alloc_functions_t:shutdown_lock()
void
pcmk__primitive_shutdown_lock(pe_resource_t *rsc)
{
    const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);

    // Fence devices and remote connections can't be locked
    if (pcmk__str_eq(class, PCMK_RESOURCE_CLASS_STONITH, pcmk__str_null_matches)
        || pe__resource_is_remote_conn(rsc, rsc->cluster)) {
        return;
    }

    if (rsc->lock_node != NULL) {
        // The lock was obtained from resource history

        if (rsc->running_on != NULL) {
            /* The resource was started elsewhere even though it is now
             * considered locked. This shouldn't be possible, but as a
             * failsafe, we don't want to disturb the resource now.
             */
            pe_rsc_info(rsc,
                        "Cancelling shutdown lock because %s is already active",
                        rsc->id);
            pe__clear_resource_history(rsc, rsc->lock_node, rsc->cluster);
            rsc->lock_node = NULL;
            rsc->lock_time = 0;
        }

    // Only a resource active on exactly one node can be locked
    } else if (pcmk__list_of_1(rsc->running_on)) {
        pe_node_t *node = rsc->running_on->data;

        if (node->details->shutdown) {
            if (node->details->unclean) {
                pe_rsc_debug(rsc, "Not locking %s to unclean %s for shutdown",
                             rsc->id, pe__node_name(node));
            } else {
                rsc->lock_node = node;
                rsc->lock_time = shutdown_time(node, rsc->cluster);
            }
        }
    }

    if (rsc->lock_node == NULL) {
        // No lock needed
        return;
    }

    if (rsc->cluster->shutdown_lock > 0) {
        time_t lock_expiration = rsc->lock_time + rsc->cluster->shutdown_lock;

        pe_rsc_info(rsc, "Locking %s to %s due to shutdown (expires @%lld)",
                    rsc->id, pe__node_name(rsc->lock_node),
                    (long long) lock_expiration);
        pe__update_recheck_time(++lock_expiration, rsc->cluster);
    } else {
        pe_rsc_info(rsc, "Locking %s to %s due to shutdown",
                    rsc->id, pe__node_name(rsc->lock_node));
    }

    // If resource is locked to one node, ban it from all other nodes
    for (GList *item = rsc->cluster->nodes; item != NULL; item = item->next) {
        pe_node_t *node = item->data;

        if (strcmp(node->details->uname, rsc->lock_node->details->uname)) {
            resource_location(rsc, node, -CRM_SCORE_INFINITY,
                              XML_CONFIG_ATTR_SHUTDOWN_LOCK, rsc->cluster);
        }
    }
}

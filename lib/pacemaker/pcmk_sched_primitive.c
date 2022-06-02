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
#include <crm/pengine/rules.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

static void Recurring(pe_resource_t *rsc, pe_action_t *start, pe_node_t *node,
                      pe_working_set_t *data_set);
static void RecurringOp(pe_resource_t *rsc, pe_action_t *start, pe_node_t *node,
                        xmlNode *operation, pe_working_set_t *data_set);
static void Recurring_Stopped(pe_resource_t *rsc, pe_action_t *start, pe_node_t *node,
                              pe_working_set_t *data_set);
static void RecurringOp_Stopped(pe_resource_t *rsc, pe_action_t *start, pe_node_t *node,
                                xmlNode *operation, pe_working_set_t *data_set);

gboolean DeleteRsc(pe_resource_t * rsc, pe_node_t * node, gboolean optional, pe_working_set_t * data_set);
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
                         prefer->details->uname, rsc->id);

        /* Favor the preferred node as long as its weight is at least as good as
         * the best allowed node's.
         *
         * An alternative would be to favor the preferred node even if the best
         * node is better, when the best node's weight is less than INFINITY.
         */
        } else if (chosen->weight < best->weight) {
            pe_rsc_trace(rsc, "Preferred node %s for %s was unsuitable",
                         chosen->details->uname, rsc->id);
            chosen = NULL;

        } else if (!pcmk__node_available(chosen, true, false)) {
            pe_rsc_trace(rsc, "Preferred node %s for %s was unavailable",
                         chosen->details->uname, rsc->id);
            chosen = NULL;

        } else {
            pe_rsc_trace(rsc,
                         "Chose preferred node %s for %s (ignoring %d candidates)",
                         chosen->details->uname, rsc->id, g_list_length(nodes));
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
                             rsc->id, running->details->uname);

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
                               "Chose node %s for %s from %d nodes with score %s",
                               chosen->details->uname, rsc->id,
                               nodes_with_best_score,
                               pcmk_readable_score(chosen->weight));
                }
            }
        }

        pe_rsc_trace(rsc, "Chose node %s for %s from %d candidates",
                     chosen->details->uname, rsc->id, g_list_length(nodes));
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
 * \brief Assign a primitive resource to a node
 *
 * \param[in] rsc     Resource to assign to a node
 * \param[in] prefer  Node to prefer, if all else is equal
 *
 * \return Node that \p rsc is assigned to, if assigned entirely to one node
 */
pe_node_t *
pcmk__native_allocate(pe_resource_t *rsc, pe_node_t *prefer)
{
    GList *gIter = NULL;

    if (rsc->parent && !pcmk_is_set(rsc->parent->flags, pe_rsc_allocating)) {
        /* never allocate children on their own */
        pe_rsc_debug(rsc, "Escalating allocation of %s to its parent: %s", rsc->id,
                     rsc->parent->id);
        rsc->parent->cmds->assign(rsc->parent, prefer);
    }

    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        return rsc->allocated_to;
    }

    if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        pe_rsc_debug(rsc, "Dependency loop detected involving %s", rsc->id);
        return NULL;
    }

    pe__set_resource_flags(rsc, pe_rsc_allocating);
    pe__show_node_weights(true, rsc, "Pre-alloc", rsc->allowed_nodes,
                          rsc->cluster);


    g_list_foreach(rsc->rsc_cons, apply_this_with, rsc);
    pe__show_node_weights(true, rsc, "Post-this-with", rsc->allowed_nodes,
                          rsc->cluster);

    for (gIter = rsc->rsc_cons_lhs; gIter != NULL; gIter = gIter->next) {
        pcmk__colocation_t *constraint = (pcmk__colocation_t *) gIter->data;
        pe_resource_t *dependent = constraint->dependent;
        const float factor = constraint->score / (float) INFINITY;

        if (!pcmk__colocation_has_influence(constraint, NULL)) {
            continue;
        }
        pe_rsc_trace(rsc, "Merging score of '%s' constraint (%s with %s)",
                     constraint->id, constraint->dependent->id,
                     constraint->primary->id);
        dependent->cmds->add_colocated_node_scores(dependent, rsc->id,
                                                   &rsc->allowed_nodes,
                                                   constraint->node_attribute,
                                                   factor,
                                                   pcmk__coloc_select_active);
    }

    if (rsc->next_role == RSC_ROLE_STOPPED) {
        pe_rsc_trace(rsc, "Making sure %s doesn't get allocated", rsc->id);
        /* make sure it doesn't come up again */
        resource_location(rsc, NULL, -INFINITY, XML_RSC_ATTR_TARGET_ROLE,
                          rsc->cluster);

    } else if(rsc->next_role > rsc->role
              && !pcmk_is_set(rsc->cluster->flags, pe_flag_have_quorum)
              && rsc->cluster->no_quorum_policy == no_quorum_freeze) {
        crm_notice("Resource %s cannot be elevated from %s to %s: no-quorum-policy=freeze",
                   rsc->id, role2text(rsc->role), role2text(rsc->next_role));
        pe__set_next_role(rsc, rsc->role, "no-quorum-policy=freeze");
    }

    pe__show_node_weights(!pcmk_is_set(rsc->cluster->flags, pe_flag_show_scores),
                          rsc, __func__, rsc->allowed_nodes, rsc->cluster);
    if (pcmk_is_set(rsc->cluster->flags, pe_flag_stonith_enabled)
        && !pcmk_is_set(rsc->cluster->flags, pe_flag_have_stonith_resource)) {
        pe__clear_resource_flags(rsc, pe_rsc_managed);
    }

    if (!pcmk_is_set(rsc->flags, pe_rsc_managed)) {
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
        pe_rsc_info(rsc, "Unmanaged resource %s allocated to %s: %s", rsc->id,
                    (assign_to? assign_to->details->uname : "no node"), reason);
        pcmk__assign_primitive(rsc, assign_to, true);

    } else if (pcmk_is_set(rsc->cluster->flags, pe_flag_stop_everything)) {
        pe_rsc_debug(rsc, "Forcing %s to stop", rsc->id);
        pcmk__assign_primitive(rsc, NULL, true);

    } else if (pcmk_is_set(rsc->flags, pe_rsc_provisional)
               && assign_best_node(rsc, prefer)) {
        pe_rsc_trace(rsc, "Allocated resource %s to %s", rsc->id,
                     rsc->allocated_to->details->uname);

    } else if (rsc->allocated_to == NULL) {
        if (!pcmk_is_set(rsc->flags, pe_rsc_orphan)) {
            pe_rsc_info(rsc, "Resource %s cannot run anywhere", rsc->id);
        } else if (rsc->running_on != NULL) {
            pe_rsc_info(rsc, "Stopping orphan resource %s", rsc->id);
        }

    } else {
        pe_rsc_debug(rsc, "Pre-Allocated resource %s to %s", rsc->id,
                     rsc->allocated_to->details->uname);
    }

    pe__clear_resource_flags(rsc, pe_rsc_allocating);

    if (rsc->is_remote_node) {
        pe_node_t *remote_node = pe_find_node(rsc->cluster->nodes, rsc->id);

        CRM_ASSERT(remote_node != NULL);
        if (rsc->allocated_to && rsc->next_role != RSC_ROLE_STOPPED) {
            crm_trace("Setting Pacemaker Remote node %s to ONLINE",
                      remote_node->details->id);
            remote_node->details->online = TRUE;
            /* We shouldn't consider an unseen remote-node unclean if we are going
             * to try and connect to it. Otherwise we get an unnecessary fence */
            if (remote_node->details->unseen == TRUE) {
                remote_node->details->unclean = FALSE;
            }

        } else {
            crm_trace("Setting Pacemaker Remote node %s to SHUTDOWN (next role %s, %sallocated)",
                      remote_node->details->id, role2text(rsc->next_role),
                      (rsc->allocated_to? "" : "un"));
            remote_node->details->shutdown = TRUE;
        }
    }

    return rsc->allocated_to;
}

static gboolean
is_op_dup(pe_resource_t *rsc, const char *name, guint interval_ms)
{
    gboolean dup = FALSE;
    const char *id = NULL;
    const char *value = NULL;
    xmlNode *operation = NULL;
    guint interval2_ms = 0;

    CRM_ASSERT(rsc);
    for (operation = pcmk__xe_first_child(rsc->ops_xml); operation != NULL;
         operation = pcmk__xe_next(operation)) {

        if (pcmk__str_eq((const char *)operation->name, "op", pcmk__str_none)) {
            value = crm_element_value(operation, "name");
            if (!pcmk__str_eq(value, name, pcmk__str_casei)) {
                continue;
            }

            value = crm_element_value(operation, XML_LRM_ATTR_INTERVAL);
            interval2_ms = crm_parse_interval_spec(value);
            if (interval_ms != interval2_ms) {
                continue;
            }

            if (id == NULL) {
                id = ID(operation);

            } else {
                pcmk__config_err("Operation %s is duplicate of %s (do not use "
                                 "same name and interval combination more "
                                 "than once per resource)", ID(operation), id);
                dup = TRUE;
            }
        }
    }

    return dup;
}

static bool
op_cannot_recur(const char *name)
{
    return pcmk__strcase_any_of(name, RSC_STOP, RSC_START, RSC_DEMOTE, RSC_PROMOTE, NULL);
}

static void
RecurringOp(pe_resource_t * rsc, pe_action_t * start, pe_node_t * node,
            xmlNode * operation, pe_working_set_t * data_set)
{
    char *key = NULL;
    const char *name = NULL;
    const char *role = NULL;
    const char *interval_spec = NULL;
    const char *node_uname = node? node->details->uname : "n/a";

    guint interval_ms = 0;
    pe_action_t *mon = NULL;
    gboolean is_optional = TRUE;
    GList *possible_matches = NULL;

    CRM_ASSERT(rsc);

    /* Only process for the operations without role="Stopped" */
    role = crm_element_value(operation, "role");
    if (role && text2role(role) == RSC_ROLE_STOPPED) {
        return;
    }

    interval_spec = crm_element_value(operation, XML_LRM_ATTR_INTERVAL);
    interval_ms = crm_parse_interval_spec(interval_spec);
    if (interval_ms == 0) {
        return;
    }

    name = crm_element_value(operation, "name");
    if (is_op_dup(rsc, name, interval_ms)) {
        crm_trace("Not creating duplicate recurring action %s for %dms %s",
                  ID(operation), interval_ms, name);
        return;
    }

    if (op_cannot_recur(name)) {
        pcmk__config_err("Ignoring %s because action '%s' cannot be recurring",
                         ID(operation), name);
        return;
    }

    key = pcmk__op_key(rsc->id, name, interval_ms);
    if (find_rsc_op_entry(rsc, key) == NULL) {
        crm_trace("Not creating recurring action %s for disabled resource %s",
                  ID(operation), rsc->id);
        free(key);
        return;
    }

    pe_rsc_trace(rsc, "Creating recurring action %s for %s in role %s on %s",
                 ID(operation), rsc->id, role2text(rsc->next_role), node_uname);

    if (start != NULL) {
        pe_rsc_trace(rsc, "Marking %s %s due to %s", key,
                     pcmk_is_set(start->flags, pe_action_optional)? "optional" : "mandatory",
                     start->uuid);
        is_optional = (rsc->cmds->action_flags(start, NULL) & pe_action_optional);
    } else {
        pe_rsc_trace(rsc, "Marking %s optional", key);
        is_optional = TRUE;
    }

    /* start a monitor for an already active resource */
    possible_matches = find_actions_exact(rsc->actions, key, node);
    if (possible_matches == NULL) {
        is_optional = FALSE;
        pe_rsc_trace(rsc, "Marking %s mandatory: not active", key);

    } else {
        GList *gIter = NULL;

        for (gIter = possible_matches; gIter != NULL; gIter = gIter->next) {
            pe_action_t *op = (pe_action_t *) gIter->data;

            if (pcmk_is_set(op->flags, pe_action_reschedule)) {
                is_optional = FALSE;
                break;
            }
        }
        g_list_free(possible_matches);
    }

    if (((rsc->next_role == RSC_ROLE_PROMOTED) && (role == NULL))
        || (role != NULL && text2role(role) != rsc->next_role)) {
        int log_level = LOG_TRACE;
        const char *result = "Ignoring";

        if (is_optional) {
            char *after_key = NULL;
            pe_action_t *cancel_op = NULL;

            // It's running, so cancel it
            log_level = LOG_INFO;
            result = "Cancelling";
            cancel_op = pcmk__new_cancel_action(rsc, name, interval_ms, node);

            switch (rsc->role) {
                case RSC_ROLE_UNPROMOTED:
                case RSC_ROLE_STARTED:
                    if (rsc->next_role == RSC_ROLE_PROMOTED) {
                        after_key = promote_key(rsc);

                    } else if (rsc->next_role == RSC_ROLE_STOPPED) {
                        after_key = stop_key(rsc);
                    }

                    break;
                case RSC_ROLE_PROMOTED:
                    after_key = demote_key(rsc);
                    break;
                default:
                    break;
            }

            if (after_key) {
                pcmk__new_ordering(rsc, NULL, cancel_op, rsc, after_key, NULL,
                                   pe_order_runnable_left, data_set);
            }
        }

        do_crm_log(log_level, "%s action %s (%s vs. %s)",
                   result, key, role ? role : role2text(RSC_ROLE_UNPROMOTED),
                   role2text(rsc->next_role));

        free(key);
        return;
    }

    mon = custom_action(rsc, key, name, node, is_optional, TRUE, data_set);
    key = mon->uuid;
    if (is_optional) {
        pe_rsc_trace(rsc, "%s\t   %s (optional)", node_uname, mon->uuid);
    }

    if ((start == NULL) || !pcmk_is_set(start->flags, pe_action_runnable)) {
        pe_rsc_debug(rsc, "%s\t   %s (cancelled : start un-runnable)",
                     node_uname, mon->uuid);
        pe__clear_action_flags(mon, pe_action_runnable);

    } else if (node == NULL || node->details->online == FALSE || node->details->unclean) {
        pe_rsc_debug(rsc, "%s\t   %s (cancelled : no node available)",
                     node_uname, mon->uuid);
        pe__clear_action_flags(mon, pe_action_runnable);

    } else if (!pcmk_is_set(mon->flags, pe_action_optional)) {
        pe_rsc_info(rsc, " Start recurring %s (%us) for %s on %s",
                    mon->task, interval_ms / 1000, rsc->id, node_uname);
    }

    if (rsc->next_role == RSC_ROLE_PROMOTED) {
        pe__add_action_expected_result(mon, CRM_EX_PROMOTED);
    }

    if ((node == NULL) || pcmk_is_set(rsc->flags, pe_rsc_managed)) {
        pcmk__new_ordering(rsc, start_key(rsc), NULL, NULL, strdup(key), mon,
                           pe_order_implies_then|pe_order_runnable_left,
                           data_set);

        pcmk__new_ordering(rsc, reload_key(rsc), NULL, NULL, strdup(key), mon,
                           pe_order_implies_then|pe_order_runnable_left,
                           data_set);

        if (rsc->next_role == RSC_ROLE_PROMOTED) {
            pcmk__new_ordering(rsc, promote_key(rsc), NULL, rsc, NULL, mon,
                               pe_order_optional|pe_order_runnable_left,
                               data_set);

        } else if (rsc->role == RSC_ROLE_PROMOTED) {
            pcmk__new_ordering(rsc, demote_key(rsc), NULL, rsc, NULL, mon,
                               pe_order_optional|pe_order_runnable_left,
                               data_set);
        }
    }
}

static void
Recurring(pe_resource_t * rsc, pe_action_t * start, pe_node_t * node, pe_working_set_t * data_set)
{
    if (!pcmk_is_set(rsc->flags, pe_rsc_maintenance) &&
        (node == NULL || node->details->maintenance == FALSE)) {
        xmlNode *operation = NULL;

        for (operation = pcmk__xe_first_child(rsc->ops_xml);
             operation != NULL;
             operation = pcmk__xe_next(operation)) {

            if (pcmk__str_eq((const char *)operation->name, "op", pcmk__str_none)) {
                RecurringOp(rsc, start, node, operation, data_set);
            }
        }
    }
}

static void
RecurringOp_Stopped(pe_resource_t * rsc, pe_action_t * start, pe_node_t * node,
                    xmlNode * operation, pe_working_set_t * data_set)
{
    char *key = NULL;
    const char *name = NULL;
    const char *role = NULL;
    const char *interval_spec = NULL;
    const char *node_uname = node? node->details->uname : "n/a";

    guint interval_ms = 0;
    GList *possible_matches = NULL;
    GList *gIter = NULL;

    /* Only process for the operations with role="Stopped" */
    role = crm_element_value(operation, "role");
    if (role == NULL || text2role(role) != RSC_ROLE_STOPPED) {
        return;
    }

    interval_spec = crm_element_value(operation, XML_LRM_ATTR_INTERVAL);
    interval_ms = crm_parse_interval_spec(interval_spec);
    if (interval_ms == 0) {
        return;
    }

    name = crm_element_value(operation, "name");
    if (is_op_dup(rsc, name, interval_ms)) {
        crm_trace("Not creating duplicate recurring action %s for %dms %s",
                  ID(operation), interval_ms, name);
        return;
    }

    if (op_cannot_recur(name)) {
        pcmk__config_err("Ignoring %s because action '%s' cannot be recurring",
                         ID(operation), name);
        return;
    }

    key = pcmk__op_key(rsc->id, name, interval_ms);
    if (find_rsc_op_entry(rsc, key) == NULL) {
        crm_trace("Not creating recurring action %s for disabled resource %s",
                  ID(operation), rsc->id);
        free(key);
        return;
    }

    // @TODO add support
    if (!pcmk_is_set(rsc->flags, pe_rsc_unique)) {
        crm_notice("Ignoring %s (recurring monitors for Stopped role are "
                   "not supported for anonymous clones)",
                   ID(operation));
        return;
    }

    pe_rsc_trace(rsc,
                 "Creating recurring action %s for %s in role %s on nodes where it should not be running",
                 ID(operation), rsc->id, role2text(rsc->next_role));

    /* if the monitor exists on the node where the resource will be running, cancel it */
    if (node != NULL) {
        possible_matches = find_actions_exact(rsc->actions, key, node);
        if (possible_matches) {
            pe_action_t *cancel_op = NULL;

            g_list_free(possible_matches);

            cancel_op = pcmk__new_cancel_action(rsc, name, interval_ms, node);

            if ((rsc->next_role == RSC_ROLE_STARTED)
                || (rsc->next_role == RSC_ROLE_UNPROMOTED)) {
                /* rsc->role == RSC_ROLE_STOPPED: cancel the monitor before start */
                /* rsc->role == RSC_ROLE_STARTED: for a migration, cancel the monitor on the target node before start */
                pcmk__new_ordering(rsc, NULL, cancel_op, rsc, start_key(rsc),
                                   NULL, pe_order_runnable_left, data_set);
            }

            pe_rsc_info(rsc, "Cancel action %s (%s vs. %s) on %s",
                        key, role, role2text(rsc->next_role), node_uname);
        }
    }

    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        pe_node_t *stop_node = (pe_node_t *) gIter->data;
        const char *stop_node_uname = stop_node->details->uname;
        gboolean is_optional = TRUE;
        gboolean probe_is_optional = TRUE;
        gboolean stop_is_optional = TRUE;
        pe_action_t *stopped_mon = NULL;
        GList *stop_ops = NULL;
        GList *local_gIter = NULL;

        if (node && pcmk__str_eq(stop_node_uname, node_uname, pcmk__str_casei)) {
            continue;
        }

        pe_rsc_trace(rsc, "Creating recurring action %s for %s on %s",
                     ID(operation), rsc->id,
                     pcmk__s(stop_node_uname, "unknown node"));

        /* start a monitor for an already stopped resource */
        possible_matches = find_actions_exact(rsc->actions, key, stop_node);
        if (possible_matches == NULL) {
            pe_rsc_trace(rsc, "Marking %s mandatory on %s: not active", key,
                         pcmk__s(stop_node_uname, "unknown node"));
            is_optional = FALSE;
        } else {
            pe_rsc_trace(rsc, "Marking %s optional on %s: already active", key,
                         pcmk__s(stop_node_uname, "unknown node"));
            is_optional = TRUE;
            g_list_free(possible_matches);
        }

        stopped_mon = custom_action(rsc, strdup(key), name, stop_node, is_optional, TRUE, data_set);

        pe__add_action_expected_result(stopped_mon, CRM_EX_NOT_RUNNING);

        if (pcmk_is_set(rsc->flags, pe_rsc_managed)) {
            GList *probes = pe__resource_actions(rsc, stop_node, RSC_STATUS,
                                                 FALSE);
            GList *pIter = NULL;

            for (pIter = probes; pIter != NULL; pIter = pIter->next) {
                pe_action_t *probe = (pe_action_t *) pIter->data;

                order_actions(probe, stopped_mon, pe_order_runnable_left);
                crm_trace("%s then %s on %s", probe->uuid, stopped_mon->uuid, stop_node->details->uname);
            }

            g_list_free(probes);
        }

        stop_ops = pe__resource_actions(rsc, stop_node, RSC_STOP, TRUE);

        for (local_gIter = stop_ops; local_gIter != NULL; local_gIter = local_gIter->next) {
            pe_action_t *stop = (pe_action_t *) local_gIter->data;

            if (!pcmk_is_set(stop->flags, pe_action_optional)) {
                stop_is_optional = FALSE;
            }

            if (!pcmk_is_set(stop->flags, pe_action_runnable)) {
                crm_debug("%s\t   %s (cancelled : stop un-runnable)",
                          pcmk__s(stop_node_uname, "<null>"),
                          stopped_mon->uuid);
                pe__clear_action_flags(stopped_mon, pe_action_runnable);
            }

            if (pcmk_is_set(rsc->flags, pe_rsc_managed)) {
                pcmk__new_ordering(rsc, stop_key(rsc), stop, NULL, strdup(key),
                                   stopped_mon,
                                   pe_order_implies_then|pe_order_runnable_left,
                                   data_set);
            }

        }

        if (stop_ops) {
            g_list_free(stop_ops);
        }

        if (is_optional == FALSE && probe_is_optional && stop_is_optional
            && !pcmk_is_set(rsc->flags, pe_rsc_managed)) {
            pe_rsc_trace(rsc, "Marking %s optional on %s due to unmanaged",
                         key, pcmk__s(stop_node_uname, "unknown node"));
            pe__set_action_flags(stopped_mon, pe_action_optional);
        }

        if (pcmk_is_set(stopped_mon->flags, pe_action_optional)) {
            pe_rsc_trace(rsc, "%s\t   %s (optional)",
                         pcmk__s(stop_node_uname, "<null>"),
                         stopped_mon->uuid);
        }

        if (stop_node->details->online == FALSE || stop_node->details->unclean) {
            pe_rsc_debug(rsc, "%s\t   %s (cancelled : no node available)",
                         pcmk__s(stop_node_uname, "<null>"),
                         stopped_mon->uuid);
            pe__clear_action_flags(stopped_mon, pe_action_runnable);
        }

        if (pcmk_is_set(stopped_mon->flags, pe_action_runnable)
            && !pcmk_is_set(stopped_mon->flags, pe_action_optional)) {
            crm_notice(" Start recurring %s (%us) for %s on %s", stopped_mon->task,
                       interval_ms / 1000, rsc->id,
                       pcmk__s(stop_node_uname, "unknown node"));
        }
    }

    free(key);
}

static void
Recurring_Stopped(pe_resource_t * rsc, pe_action_t * start, pe_node_t * node, pe_working_set_t * data_set)
{
    if (!pcmk_is_set(rsc->flags, pe_rsc_maintenance) &&
        (node == NULL || node->details->maintenance == FALSE)) {
        xmlNode *operation = NULL;

        for (operation = pcmk__xe_first_child(rsc->ops_xml);
             operation != NULL;
             operation = pcmk__xe_next(operation)) {

            if (pcmk__str_eq((const char *)operation->name, "op", pcmk__str_none)) {
                RecurringOp_Stopped(rsc, start, node, operation, data_set);
            }
        }
    }
}

static void
handle_migration_actions(pe_resource_t * rsc, pe_node_t *current, pe_node_t *chosen, pe_working_set_t * data_set)
{
    pe_action_t *migrate_to = NULL;
    pe_action_t *migrate_from = NULL;
    pe_action_t *start = NULL;
    pe_action_t *stop = NULL;
    gboolean partial = rsc->partial_migration_target ? TRUE : FALSE;

    pe_rsc_trace(rsc, "Processing migration actions %s moving from %s to %s . partial migration = %s",
    rsc->id, current->details->id, chosen->details->id, partial ? "TRUE" : "FALSE");
    start = start_action(rsc, chosen, TRUE);
    stop = stop_action(rsc, current, TRUE);

    if (partial == FALSE) {
        migrate_to = custom_action(rsc, pcmk__op_key(rsc->id, RSC_MIGRATE, 0),
                                   RSC_MIGRATE, current, TRUE, TRUE, data_set);
    }

    migrate_from = custom_action(rsc, pcmk__op_key(rsc->id, RSC_MIGRATED, 0),
                                 RSC_MIGRATED, chosen, TRUE, TRUE, data_set);

    if ((migrate_to && migrate_from) || (migrate_from && partial)) {

        pe__set_action_flags(start, pe_action_migrate_runnable);
        pe__set_action_flags(stop, pe_action_migrate_runnable);

        // This is easier than trying to delete it from the graph
        pe__set_action_flags(start, pe_action_pseudo);

        /* order probes before migrations */
        if (partial) {
            pe__set_action_flags(migrate_from, pe_action_migrate_runnable);
            migrate_from->needs = start->needs;

            pcmk__new_ordering(rsc, pcmk__op_key(rsc->id, RSC_STATUS, 0), NULL,
                               rsc, pcmk__op_key(rsc->id, RSC_MIGRATED, 0),
                               NULL, pe_order_optional, data_set);

        } else {
            pe__set_action_flags(migrate_from, pe_action_migrate_runnable);
            pe__set_action_flags(migrate_to, pe_action_migrate_runnable);
            migrate_to->needs = start->needs;

            pcmk__new_ordering(rsc, pcmk__op_key(rsc->id, RSC_STATUS, 0), NULL,
                               rsc, pcmk__op_key(rsc->id, RSC_MIGRATE, 0),
                               NULL, pe_order_optional, data_set);
            pcmk__new_ordering(rsc, pcmk__op_key(rsc->id, RSC_MIGRATE, 0), NULL,
                               rsc, pcmk__op_key(rsc->id, RSC_MIGRATED, 0),
                               NULL,
                               pe_order_optional|pe_order_implies_first_migratable,
                               data_set);
        }

        pcmk__new_ordering(rsc, pcmk__op_key(rsc->id, RSC_MIGRATED, 0), NULL,
                           rsc, pcmk__op_key(rsc->id, RSC_STOP, 0), NULL,
                           pe_order_optional|pe_order_implies_first_migratable,
                           data_set);
        pcmk__new_ordering(rsc, pcmk__op_key(rsc->id, RSC_MIGRATED, 0), NULL,
                           rsc, pcmk__op_key(rsc->id, RSC_START, 0), NULL,
                           pe_order_optional|pe_order_implies_first_migratable|pe_order_pseudo_left,
                           data_set);
    }

    if (migrate_to) {
        add_hash_param(migrate_to->meta, XML_LRM_ATTR_MIGRATE_SOURCE, current->details->uname);
        add_hash_param(migrate_to->meta, XML_LRM_ATTR_MIGRATE_TARGET, chosen->details->uname);

        /* Pacemaker Remote connections don't require pending to be recorded in
         * the CIB. We can reduce CIB writes by not setting PENDING for them.
         */
        if (rsc->is_remote_node == FALSE) {
            /* migrate_to takes place on the source node, but can 
             * have an effect on the target node depending on how
             * the agent is written. Because of this, we have to maintain
             * a record that the migrate_to occurred, in case the source node
             * loses membership while the migrate_to action is still in-flight.
             */
            add_hash_param(migrate_to->meta, XML_OP_ATTR_PENDING, "true");
        }
    }

    if (migrate_from) {
        add_hash_param(migrate_from->meta, XML_LRM_ATTR_MIGRATE_SOURCE, current->details->uname);
        add_hash_param(migrate_from->meta, XML_LRM_ATTR_MIGRATE_TARGET, chosen->details->uname);
    }
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

void
native_create_actions(pe_resource_t *rsc)
{
    pe_action_t *start = NULL;
    pe_node_t *chosen = NULL;
    pe_node_t *current = NULL;
    gboolean need_stop = FALSE;
    bool need_promote = FALSE;
    gboolean is_moving = FALSE;
    gboolean allow_migrate = FALSE;

    GList *gIter = NULL;
    unsigned int num_all_active = 0;
    unsigned int num_clean_active = 0;
    bool multiply_active = FALSE;
    enum rsc_role_e role = RSC_ROLE_UNKNOWN;
    enum rsc_role_e next_role = RSC_ROLE_UNKNOWN;

    CRM_ASSERT(rsc != NULL);
    allow_migrate = pcmk_is_set(rsc->flags, pe_rsc_allow_migrate)? TRUE : FALSE;

    chosen = rsc->allocated_to;
    next_role = rsc->next_role;
    if (next_role == RSC_ROLE_UNKNOWN) {
        pe__set_next_role(rsc,
                          (chosen == NULL)? RSC_ROLE_STOPPED : RSC_ROLE_STARTED,
                          "allocation");
    }
    pe_rsc_trace(rsc, "Creating all actions for %s transition from %s to %s (%s) on %s",
                 rsc->id, role2text(rsc->role), role2text(rsc->next_role),
                 ((next_role == RSC_ROLE_UNKNOWN)? "implicit" : "explicit"),
                 ((chosen == NULL)? "no node" : chosen->details->uname));

    current = pe__find_active_on(rsc, &num_all_active, &num_clean_active);

    for (gIter = rsc->dangling_migrations; gIter != NULL; gIter = gIter->next) {
        pe_node_t *dangling_source = (pe_node_t *) gIter->data;

        pe_action_t *stop = NULL;

        pe_rsc_trace(rsc, "Creating stop action %sfor %s on %s due to dangling migration",
                     pcmk_is_set(rsc->cluster->flags, pe_flag_remove_after_stop)? "and cleanup " : "",
                     rsc->id, dangling_source->details->uname);
        stop = stop_action(rsc, dangling_source, FALSE);
        pe__set_action_flags(stop, pe_action_dangle);
        if (pcmk_is_set(rsc->cluster->flags, pe_flag_remove_after_stop)) {
            DeleteRsc(rsc, dangling_source, FALSE, rsc->cluster);
        }
    }

    if ((num_all_active == 2) && (num_clean_active == 2) && chosen
        && rsc->partial_migration_source && rsc->partial_migration_target
        && (current->details == rsc->partial_migration_source->details)
        && (chosen->details == rsc->partial_migration_target->details)) {

        /* The chosen node is still the migration target from a partial
         * migration. Attempt to continue the migration instead of recovering
         * by stopping the resource everywhere and starting it on a single node.
         */
        pe_rsc_trace(rsc, "Will attempt to continue with partial migration "
                     "to target %s from %s",
                     rsc->partial_migration_target->details->id,
                     rsc->partial_migration_source->details->id);

    } else if (!pcmk_is_set(rsc->flags, pe_rsc_needs_fencing)) {
        /* If a resource has "requires" set to nothing or quorum, don't consider
         * it active on unclean nodes (similar to how all resources behave when
         * stonith-enabled is false). We can start such resources elsewhere
         * before fencing completes, and if we considered the resource active on
         * the failed node, we would attempt recovery for being active on
         * multiple nodes.
         */
        multiply_active = (num_clean_active > 1);
    } else {
        multiply_active = (num_all_active > 1);
    }

    if (multiply_active) {
        if (rsc->partial_migration_target && rsc->partial_migration_source) {
            // Migration was in progress, but we've chosen a different target
            crm_notice("Resource %s can no longer migrate from %s to %s "
                       "(will stop on both nodes)",
                       rsc->id, rsc->partial_migration_source->details->uname,
                       rsc->partial_migration_target->details->uname);
            multiply_active = false;

        } else {
            const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);

            // Resource was (possibly) incorrectly multiply active
            pe_proc_err("%s resource %s might be active on %u nodes (%s)",
                        pcmk__s(class, "Untyped"), rsc->id, num_all_active,
                        recovery2text(rsc->recovery_type));
            crm_notice("See https://wiki.clusterlabs.org/wiki/FAQ#Resource_is_Too_Active for more information");
        }

        switch (rsc->recovery_type) {
            case recovery_stop_start:
                need_stop = TRUE;
                break;
            case recovery_stop_unexpected:
                need_stop = TRUE; // StopRsc() will skip expected node
                pe__set_resource_flags(rsc, pe_rsc_stop_unexpected);
                break;
            default:
                break;
        }

        /* If by chance a partial migration is in process, but the migration
         * target is not chosen still, clear all partial migration data.
         */
        rsc->partial_migration_source = rsc->partial_migration_target = NULL;
        allow_migrate = FALSE;
    }

    if (!multiply_active) {
        pe__clear_resource_flags(rsc, pe_rsc_stop_unexpected);
    }

    if (pcmk_is_set(rsc->flags, pe_rsc_start_pending)) {
        pe_rsc_trace(rsc, "Creating start action for %s to represent already pending start",
                     rsc->id);
        start = start_action(rsc, chosen, TRUE);
        pe__set_action_flags(start, pe_action_print_always);
    }

    if (current && chosen && current->details != chosen->details) {
        pe_rsc_trace(rsc, "Moving %s from %s to %s",
                     rsc->id, pcmk__s(current->details->uname, "unknown node"),
                     pcmk__s(chosen->details->uname, "unknown node"));
        is_moving = TRUE;
        need_stop = TRUE;

    } else if (pcmk_is_set(rsc->flags, pe_rsc_failed)) {
        if (pcmk_is_set(rsc->flags, pe_rsc_stop)) {
            need_stop = TRUE;
            pe_rsc_trace(rsc, "Recovering %s", rsc->id);
        } else {
            pe_rsc_trace(rsc, "Recovering %s by demotion", rsc->id);
            if (rsc->next_role == RSC_ROLE_PROMOTED) {
                need_promote = TRUE;
            }
        }

    } else if (pcmk_is_set(rsc->flags, pe_rsc_block)) {
        pe_rsc_trace(rsc, "Blocking further actions on %s", rsc->id);
        need_stop = TRUE;

    } else if (rsc->role > RSC_ROLE_STARTED && current != NULL && chosen != NULL) {
        pe_rsc_trace(rsc, "Creating start action for promoted resource %s",
                     rsc->id);
        start = start_action(rsc, chosen, TRUE);
        if (!pcmk_is_set(start->flags, pe_action_optional)) {
            // Recovery of a promoted resource
            pe_rsc_trace(rsc, "%s restart is required for recovery", rsc->id);
            need_stop = TRUE;
        }
    }

    /* Create any additional actions required when bringing resource down and
     * back up to same level.
     */
    schedule_restart_actions(rsc, current, chosen, need_stop, need_promote);

    /* Required steps from this role to the next */
    role = rsc->role;
    while (role != rsc->next_role) {
        next_role = rsc_state_matrix[role][rsc->next_role];
        pe_rsc_trace(rsc, "Creating action to take %s from %s to %s (ending at %s)",
                     rsc->id, role2text(role), role2text(next_role),
                     role2text(rsc->next_role));
        if (!rsc_action_matrix[role][next_role](rsc, chosen, false)) {
            break;
        }
        role = next_role;
    }

    if (pcmk_is_set(rsc->flags, pe_rsc_block)) {
        pe_rsc_trace(rsc, "Not creating recurring monitors for blocked resource %s",
                     rsc->id);

    } else if ((rsc->next_role != RSC_ROLE_STOPPED)
               || !pcmk_is_set(rsc->flags, pe_rsc_managed)) {
        pe_rsc_trace(rsc, "Creating recurring monitors for %s resource %s",
                     ((rsc->next_role == RSC_ROLE_STOPPED)? "unmanaged" : "active"),
                     rsc->id);
        start = start_action(rsc, chosen, TRUE);
        Recurring(rsc, start, chosen, rsc->cluster);
        Recurring_Stopped(rsc, start, chosen, rsc->cluster);

    } else {
        pe_rsc_trace(rsc, "Creating recurring monitors for inactive resource %s",
                     rsc->id);
        Recurring_Stopped(rsc, NULL, NULL, rsc->cluster);
    }

    /* if we are stuck in a partial migration, where the target
     * of the partial migration no longer matches the chosen target.
     * A full stop/start is required */
    if (rsc->partial_migration_target && (chosen == NULL || rsc->partial_migration_target->details != chosen->details)) {
        pe_rsc_trace(rsc, "Not allowing partial migration of %s to continue",
                     rsc->id);
        allow_migrate = FALSE;

    } else if (!is_moving || !pcmk_is_set(rsc->flags, pe_rsc_managed)
               || pcmk_any_flags_set(rsc->flags,
                                     pe_rsc_failed|pe_rsc_start_pending)
               || (current && current->details->unclean)
               || rsc->next_role < RSC_ROLE_STARTED) {

        allow_migrate = FALSE;
    }

    if (allow_migrate) {
        handle_migration_actions(rsc, current, chosen, rsc->cluster);
    }
}

static void
rsc_avoids_remote_nodes(pe_resource_t *rsc)
{
    GHashTableIter iter;
    pe_node_t *node = NULL;
    g_hash_table_iter_init(&iter, rsc->allowed_nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
        if (node->details->remote_rsc) {
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

void
native_internal_constraints(pe_resource_t *rsc)
{
    /* This function is on the critical path and worth optimizing as much as possible */

    pe_resource_t *top = NULL;
    GList *allowed_nodes = NULL;
    bool check_unfencing = FALSE;
    bool check_utilization = false;

    if (!pcmk_is_set(rsc->flags, pe_rsc_managed)) {
        pe_rsc_trace(rsc,
                     "Skipping native constraints for unmanaged resource: %s",
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
    if (check_unfencing || check_utilization || rsc->container) {
        allowed_nodes = allowed_nodes_as_list(rsc, rsc->cluster);
    }

    if (check_unfencing) {
        /* Check if the node needs to be unfenced first */

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

    if (rsc->container) {
        pe_resource_t *remote_rsc = NULL;

        if (rsc->is_remote_node) {
            // rsc is the implicit remote connection for a guest or bundle node

            /* Do not allow a guest resource to live on a Pacemaker Remote node,
             * to avoid nesting remotes. However, allow bundles to run on remote
             * nodes.
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

        if (remote_rsc) {
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
                                 rsc->container, NULL, NULL, true, rsc->cluster);
        }
    }

    if (rsc->is_remote_node || pcmk_is_set(rsc->flags, pe_rsc_fence_device)) {
        /* don't allow remote nodes to run stonith devices
         * or remote connection resources.*/
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

enum pe_action_flags
native_action_flags(pe_action_t * action, pe_node_t * node)
{
    return action->flags;
}

void
native_rsc_location(pe_resource_t *rsc, pe__location_t *constraint)
{
    pcmk__apply_location(constraint, rsc);
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
                         rsc->id, current->details->uname);
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
                             rsc->id, current->details->uname,
                             next->details->uname);
                continue;
            } else {
                pe_rsc_trace(rsc,
                             "Forcing stop of %s on %s "
                             "because migration target changed",
                             rsc->id, current->details->uname);
                optional = false;
            }
        }

        pe_rsc_trace(rsc, "Scheduling stop of %s on %s",
                     rsc->id, current->details->uname);
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
                pe_proc_err("Stopping %s until %s can be unfenced", rsc->id, current->details->uname);
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
                 ((next == NULL)? "N/A" : next->details->uname),
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
                     rsc->id, next->details->uname);
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

    pe_rsc_trace(rsc, "%s on %s", rsc->id, next->details->uname);

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
                         rsc->id, next->details->uname);
            pe__set_action_flags(promote, pe_action_pseudo);
        }

        return true;
    }

    pe_rsc_debug(rsc, "%s\tPromote %s (canceled)", next->details->uname, rsc->id);

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
                     rsc->id, next->details->uname);
        return true;
    }

    pe_rsc_trace(rsc, "%s", rsc->id);

    /* CRM_CHECK(rsc->next_role == RSC_ROLE_UNPROMOTED, return FALSE); */
    for (gIter = rsc->running_on; gIter != NULL; gIter = gIter->next) {
        pe_node_t *current = (pe_node_t *) gIter->data;

        pe_rsc_trace(rsc, "%s on %s", rsc->id, next ? next->details->uname : "N/A");
        demote_action(rsc, current, optional);
    }
    return true;
}

static bool
RoleError(pe_resource_t *rsc, pe_node_t *next, bool optional)
{
    CRM_ASSERT(rsc);
    crm_err("%s on %s", rsc->id, next ? next->details->uname : "N/A");
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
DeleteRsc(pe_resource_t * rsc, pe_node_t * node, gboolean optional, pe_working_set_t * data_set)
{
    if (pcmk_is_set(rsc->flags, pe_rsc_failed)) {
        pe_rsc_trace(rsc, "Resource %s not deleted from %s: failed", rsc->id, node->details->uname);
        return FALSE;

    } else if (node == NULL) {
        pe_rsc_trace(rsc, "Resource %s not deleted: NULL node", rsc->id);
        return FALSE;

    } else if (node->details->unclean || node->details->online == FALSE) {
        pe_rsc_trace(rsc, "Resource %s not deleted from %s: unrunnable", rsc->id,
                     node->details->uname);
        return FALSE;
    }

    crm_notice("Removing %s from %s", rsc->id, node->details->uname);

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
                             rsc->id, node->details->uname);
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
                    rsc->id, rsc->lock_node->details->uname,
                    (long long) lock_expiration);
        pe__update_recheck_time(++lock_expiration, rsc->cluster);
    } else {
        pe_rsc_info(rsc, "Locking %s to %s due to shutdown",
                    rsc->id, rsc->lock_node->details->uname);
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

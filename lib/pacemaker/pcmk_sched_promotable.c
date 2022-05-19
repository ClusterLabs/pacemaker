/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/msg_xml.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

#define VARIANT_CLONE 1
#include <lib/pengine/variant.h>

/*!
 * \internal
 * \brief Add implicit promotion ordering for a promotable instance
 *
 * \param[in] clone  Clone resource
 * \param[in] child  Instance of \p clone being ordered
 * \param[in] last   Previous instance ordered (NULL if \p child is first)
 */
static void
order_instance_promotion(pe_resource_t *clone, pe_resource_t *child,
                         pe_resource_t *last)
{
    // "Promote clone" -> promote instance -> "clone promoted"
    pcmk__order_resource_actions(clone, RSC_PROMOTE, child, RSC_PROMOTE,
                                 pe_order_optional, clone->cluster);
    pcmk__order_resource_actions(child, RSC_PROMOTE, clone, RSC_PROMOTED,
                                 pe_order_optional, clone->cluster);

    // If clone is ordered, order this instance relative to last
    if ((last != NULL) && pe__clone_is_ordered(clone)) {
        pcmk__order_resource_actions(last, RSC_PROMOTE, child, RSC_PROMOTE,
                                     pe_order_optional, clone->cluster);
    }
}

/*!
 * \internal
 * \brief Add implicit demotion ordering for a promotable instance
 *
 * \param[in] clone  Clone resource
 * \param[in] child  Instance of \p clone being ordered
 * \param[in] last   Previous instance ordered (NULL if \p child is first)
 */
static void
order_instance_demotion(pe_resource_t *clone, pe_resource_t *child,
                        pe_resource_t *last)
{
    // "Demote clone" -> demote instance -> "clone demoted"
    pcmk__order_resource_actions(clone, RSC_DEMOTE, child, RSC_DEMOTE,
                                 pe_order_implies_first_printed,
                                 clone->cluster);
    pcmk__order_resource_actions(child, RSC_DEMOTE, clone, RSC_DEMOTED,
                                 pe_order_implies_then_printed, clone->cluster);

    // If clone is ordered, order this instance relative to last
    if ((last != NULL) && pe__clone_is_ordered(clone)) {
        pcmk__order_resource_actions(child, RSC_DEMOTE, last, RSC_DEMOTE,
                                     pe_order_optional, clone->cluster);
    }
}

/*!
 * \internal
 * \brief Check whether an instance will be promoted or demoted
 *
 * \param[in] rsc        Instance to check
 * \param[in] demoting   If \p rsc will be demoted, this will be set to true
 * \param[in] promoting  If \p rsc will be promoted, this will be set to true
 */
static void
check_for_role_change(pe_resource_t *rsc, bool *demoting, bool *promoting)
{
    GList *iter = NULL;

    // If this is a cloned group, check group members recursively
    if (rsc->children != NULL) {
        for (iter = rsc->children; iter != NULL; iter = iter->next) {
            check_for_role_change((pe_resource_t *) iter->data,
                                  demoting, promoting);
        }
        return;
    }

    for (iter = rsc->actions; iter != NULL; iter = iter->next) {
        pe_action_t *action = (pe_action_t *) iter->data;

        if (*promoting && *demoting) {
            return;

        } else if (pcmk_is_set(action->flags, pe_action_optional)) {
            continue;

        } else if (pcmk__str_eq(RSC_DEMOTE, action->task, pcmk__str_none)) {
            *demoting = true;

        } else if (pcmk__str_eq(RSC_PROMOTE, action->task, pcmk__str_none)) {
            *promoting = true;
        }
    }
}

/*!
 * \internal
 * \brief Add promoted-role location constraint scores to an instance's priority
 *
 * Adjust a promotable clone instance's promotion priority by the scores of any
 * location constraints in a list that are both limited to the promoted role and
 * for the node where the instance will be placed.
 *
 * \param[in] child                 Promotable clone instance
 * \param[in] location_constraints  List of location constraints to apply
 * \param[in] chosen                Node where \p child will be placed
 */
static void
apply_promoted_locations(pe_resource_t *child, GList *location_constraints,
                         pe_node_t *chosen)
{
    for (GList *iter = location_constraints; iter; iter = iter->next) {
        pe__location_t *location = iter->data;
        pe_node_t *weighted_node = NULL;

        if (location->role_filter == RSC_ROLE_PROMOTED) {
            weighted_node = pe_find_node_id(location->node_list_rh,
                                            chosen->details->id);
        }
        if (weighted_node != NULL) {
            int new_priority = pcmk__add_scores(child->priority,
                                                weighted_node->weight);

            pe_rsc_trace(child,
                         "Applying location %s to %s promotion priority on %s: "
                         "%d + %d = %d",
                         location->id, child->id, weighted_node->details->uname,
                         child->priority, weighted_node->weight, new_priority);
            child->priority = new_priority;
        }
    }
}

/*!
 * \internal
 * \brief Get the node that an instance will be promoted on
 *
 * \param[in] rsc  Promotable clone instance to check
 *
 * \return Node that \p rsc will be promoted on, or NULL if none
 */
static pe_node_t *
node_to_be_promoted_on(pe_resource_t *rsc)
{
    pe_node_t *node = NULL;
    pe_node_t *local_node = NULL;
    pe_resource_t *parent = uber_parent(rsc);

    // If this is a cloned group, bail if any group member can't be promoted
    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        pe_resource_t *child = (pe_resource_t *) iter->data;

        if (node_to_be_promoted_on(child) == NULL) {
            pe_rsc_trace(rsc,
                         "%s can't be promoted because member %s can't",
                         rsc->id, child->id);
            return NULL;
        }
    }

    node = rsc->fns->location(rsc, NULL, FALSE);
    if (node == NULL) {
        pe_rsc_trace(rsc, "%s can't be promoted because it won't be active",
                     rsc->id);
        return NULL;

    } else if (!pcmk_is_set(rsc->flags, pe_rsc_managed)) {
        if (rsc->fns->state(rsc, TRUE) == RSC_ROLE_PROMOTED) {
            crm_notice("Unmanaged instance %s will be left promoted on %s",
                       rsc->id, node->details->uname);
        } else {
            pe_rsc_trace(rsc, "%s can't be promoted because it is unmanaged",
                         rsc->id);
            return NULL;
        }

    } else if (rsc->priority < 0) {
        pe_rsc_trace(rsc,
                     "%s can't be promoted because its promotion priority %d "
                     "is negative",
                     rsc->id, rsc->priority);
        return NULL;

    } else if (!pcmk__node_available(node, false, true)) {
        pe_rsc_trace(rsc, "%s can't be promoted because %s can't run resources",
                     rsc->id, node->details->uname);
        return NULL;
    }

    local_node = pe_hash_table_lookup(parent->allowed_nodes, node->details->id);

    if (local_node == NULL) {
        /* It should not be possible for the scheduler to have allocated the
         * instance to a node where its parent is not allowed, but it's good to
         * have a fail-safe.
         */
        if (pcmk_is_set(rsc->flags, pe_rsc_managed)) {
            crm_warn("%s can't be promoted because %s is not allowed on %s "
                     "(scheduler bug?)",
                     rsc->id, parent->id, node->details->uname);
        } // else the instance is unmanaged and already promoted
        return NULL;

    } else if ((local_node->count >= pe__clone_promoted_node_max(parent))
               && pcmk_is_set(rsc->flags, pe_rsc_managed)) {
        pe_rsc_trace(rsc,
                     "%s can't be promoted because %s has "
                     "maximum promoted instances already",
                     rsc->id, node->details->uname);
        return NULL;
    }

    return local_node;
}

/*!
 * \internal
 * \brief Compare two promotable clone instances by promotion priority
 *
 * \param[in] a  First instance to compare
 * \param[in] b  Second instance to compare
 *
 * \return A negative number if \p a has higher promotion priority,
 *         a positive number if \p b has higher promotion priority,
 *         or 0 if promotion priorities are equal
 */
static gint
cmp_promotable_instance(gconstpointer a, gconstpointer b)
{
    const pe_resource_t *rsc1 = (const pe_resource_t *) a;
    const pe_resource_t *rsc2 = (const pe_resource_t *) b;

    enum rsc_role_e role1 = RSC_ROLE_UNKNOWN;
    enum rsc_role_e role2 = RSC_ROLE_UNKNOWN;

    CRM_ASSERT((rsc1 != NULL) && (rsc2 != NULL));

    // Check sort index set by pcmk__set_instance_roles()
    if (rsc1->sort_index > rsc2->sort_index) {
        pe_rsc_trace(rsc1,
                     "%s has higher promotion priority than %s "
                     "(sort index %d > %d)",
                     rsc1->id, rsc2->id, rsc1->sort_index, rsc2->sort_index);
        return -1;
    } else if (rsc1->sort_index < rsc2->sort_index) {
        pe_rsc_trace(rsc1,
                     "%s has lower promotion priority than %s "
                     "(sort index %d < %d)",
                     rsc1->id, rsc2->id, rsc1->sort_index, rsc2->sort_index);
        return 1;
    }

    // If those are the same, prefer instance whose current role is higher
    role1 = rsc1->fns->state(rsc1, TRUE);
    role2 = rsc2->fns->state(rsc2, TRUE);
    if (role1 > role2) {
        pe_rsc_trace(rsc1,
                     "%s has higher promotion priority than %s "
                     "(higher current role)",
                     rsc1->id, rsc2->id);
        return -1;
    } else if (role1 < role2) {
        pe_rsc_trace(rsc1,
                     "%s has lower promotion priority than %s "
                     "(lower current role)",
                     rsc1->id, rsc2->id);
        return 1;
    }

    // Finally, do normal clone instance sorting
    return pcmk__cmp_instance(a, b);
}

/*!
 * \internal
 * \brief Add a promotable clone instance's sort index to its node's weight
 *
 * Add a promotable clone instance's sort index (which sums its promotion
 * preferences and scores of relevant location constraints for the promoted
 * role) to the node weight of the instance's allocated node.
 *
 * \param[in] data       Promotable clone instance
 * \param[in] user_data  Clone parent of \p data
 */
static void
add_sort_index_to_node_weight(gpointer data, gpointer user_data)
{
    pe_resource_t *child = (pe_resource_t *) data;
    pe_resource_t *clone = (pe_resource_t *) user_data;

    pe_node_t *node = NULL;
    pe_node_t *chosen = NULL;

    if (child->sort_index < 0) {
        pe_rsc_trace(clone, "Not adding sort index of %s: negative", child->id);
        return;
    }

    chosen = child->fns->location(child, NULL, FALSE);
    if (chosen == NULL) {
        pe_rsc_trace(clone, "Not adding sort index of %s: inactive", child->id);
        return;
    }

    node = (pe_node_t *) pe_hash_table_lookup(clone->allowed_nodes,
                                              chosen->details->id);
    CRM_ASSERT(node != NULL);

    pe_rsc_trace(clone, "Adding sort index %s of %s to weight for %s",
                 pcmk_readable_score(child->sort_index), child->id,
                 node->details->uname);
    node->weight = pcmk__add_scores(child->sort_index, node->weight);
}

/*!
 * \internal
 * \brief Apply colocation to dependent's node weights if for promoted role
 *
 * \param[in] data       Colocation constraint to apply
 * \param[in] user_data  Promotable clone that is constraint's dependent
 */
static void
apply_coloc_to_dependent(gpointer data, gpointer user_data)
{
    pcmk__colocation_t *constraint = (pcmk__colocation_t *) data;
    pe_resource_t *clone = (pe_resource_t *) user_data;
    enum pe_weights flags = 0;

    if (constraint->dependent_role != RSC_ROLE_PROMOTED) {
        return;
    }
    if (constraint->score < INFINITY) {
        flags = pe_weights_rollback;
    }
    pe_rsc_trace(clone, "RHS: %s with %s: %d",
                 constraint->dependent->id, constraint->primary->id,
                 constraint->score);
    pcmk__apply_colocation(constraint, clone, constraint->primary, flags);
}

/*!
 * \internal
 * \brief Apply colocation to primary's node weights if for promoted role
 *
 * \param[in] data       Colocation constraint to apply
 * \param[in] user_data  Promotable clone that is constraint's primary
 */
static void
apply_coloc_to_primary(gpointer data, gpointer user_data)
{
    pcmk__colocation_t *constraint = (pcmk__colocation_t *) data;
    pe_resource_t *clone = (pe_resource_t *) user_data;

    if ((constraint->primary_role != RSC_ROLE_PROMOTED)
         || !pcmk__colocation_has_influence(constraint, NULL)) {
        return;
    }

    pe_rsc_trace(clone, "LHS: %s with %s: %d",
                 constraint->dependent->id, constraint->primary->id,
                 constraint->score);
    pcmk__apply_colocation(constraint, clone, constraint->dependent,
                           pe_weights_rollback|pe_weights_positive);
}

/*!
 * \internal
 * \brief Set clone instance's sort index to its node's weight
 *
 * \param[in] data       Promotable clone instance
 * \param[in] user_data  Parent clone of \p data
 */
static void
set_sort_index_to_node_weight(gpointer data, gpointer user_data)
{
    pe_resource_t *child = (pe_resource_t *) data;
    pe_resource_t *clone = (pe_resource_t *) user_data;

    pe_node_t *chosen = child->fns->location(child, NULL, FALSE);

    if (!pcmk_is_set(child->flags, pe_rsc_managed)
        && (child->next_role == RSC_ROLE_PROMOTED)) {
        child->sort_index = INFINITY;
        pe_rsc_trace(clone,
                     "Final sort index for %s is INFINITY (unmanaged promoted)",
                     child->id);

    } else if ((chosen == NULL) || (child->sort_index < 0)) {
        pe_rsc_trace(clone,
                     "Final sort index for %s is %d (ignoring node weight)",
                     child->id, child->sort_index);

    } else {
        pe_node_t *node = NULL;

        node = (pe_node_t *) pe_hash_table_lookup(clone->allowed_nodes,
                                                  chosen->details->id);
        CRM_ASSERT(node != NULL);

        child->sort_index = node->weight;
        pe_rsc_trace(clone,
                     "Merging weights for %s: final sort index for %s is %d",
                     clone->id, child->id, child->sort_index);
    }
}

/*!
 * \internal
 * \brief Sort a promotable clone's instances by descending promotion priority
 *
 * \param[in] clone  Promotable clone to sort
 */
static void
sort_promotable_instances(pe_resource_t *clone)
{
    if (pe__set_clone_flag(clone, pe__clone_promotion_constrained)
            == pcmk_rc_already) {
        return;
    }
    pe__set_resource_flags(clone, pe_rsc_merging);

    for (GList *iter = clone->children; iter != NULL; iter = iter->next) {
        pe_resource_t *child = (pe_resource_t *) iter->data;

        pe_rsc_trace(clone,
                     "Merging weights for %s: initial sort index for %s is %d",
                     clone->id, child->id, child->sort_index);
    }
    pe__show_node_weights(true, clone, "Before", clone->allowed_nodes,
                          clone->cluster);

    g_list_foreach(clone->children, add_sort_index_to_node_weight, clone);
    g_list_foreach(clone->rsc_cons, apply_coloc_to_dependent, clone);
    g_list_foreach(clone->rsc_cons_lhs, apply_coloc_to_primary, clone);

    // Ban resource from all nodes if it needs a ticket but doesn't have it
    pcmk__require_promotion_tickets(clone);

    pe__show_node_weights(true, clone, "After", clone->allowed_nodes,
                          clone->cluster);

    // Reset sort indexes to final node weights
    g_list_foreach(clone->children, set_sort_index_to_node_weight, clone);

    // Finally, sort instances in descending order of promotion priority
    clone->children = g_list_sort(clone->children, cmp_promotable_instance);
    pe__clear_resource_flags(clone, pe_rsc_merging);
}

/*!
 * \internal
 * \brief Find the active instance (if any) of an anonymous clone on a node
 *
 * \param[in] clone  Anonymous clone to check
 * \param[in] id     Instance ID (without instance number) to check
 * \param[in] node   Node to check
 *
 * \return
 */
static pe_resource_t *
find_active_anon_instance(pe_resource_t *clone, const char *id,
                          const pe_node_t *node)
{
    for (GList *iter = clone->children; iter; iter = iter->next) {
        pe_resource_t *child = iter->data;
        pe_resource_t *active = NULL;

        // Use ->find_rsc() in case this is a cloned group
        active = clone->fns->find_rsc(child, id, node,
                                      pe_find_clone|pe_find_current);
        if (active != NULL) {
            return active;
        }
    }
    return NULL;
}

/*
 * \brief Check whether an anonymous clone instance is known on a node
 *
 * \param[in] clone  Anonymous clone to check
 * \param[in] id     Instance ID (without instance number) to check
 * \param[in] node   Node to check
 *
 * \return true if \p id instance of \p clone is known on \p node,
 *         otherwise false
 */
static bool
anonymous_known_on(const pe_resource_t *clone, const char *id,
                   const pe_node_t *node)
{
    for (GList *iter = clone->children; iter; iter = iter->next) {
        pe_resource_t *child = iter->data;

        /* Use ->find_rsc() because this might be a cloned group, and knowing
         * that other members of the group are known here implies nothing.
         */
        child = clone->fns->find_rsc(child, id, NULL, pe_find_clone);
        CRM_LOG_ASSERT(child != NULL);
        if (child != NULL) {
            if (g_hash_table_lookup(child->known_on, node->details->id)) {
                return true;
            }
        }
    }
    return false;
}

/*!
 * \internal
 * \brief Check whether a node is allowed to run a resource
 *
 * \param[in] rsc   Resource to check
 * \param[in] node  Node to check
 *
 * \return true if \p node is allowed to run \p rsc, otherwise false
 */
static bool
is_allowed(const pe_resource_t *rsc, const pe_node_t *node)
{
    pe_node_t *allowed = pe_hash_table_lookup(rsc->allowed_nodes,
                                              node->details->id);

    return (allowed != NULL) && (allowed->weight >= 0);
}

/*!
 * \brief Check whether a clone instance's promotion score should be considered
 *
 * \param[in] rsc   Promotable clone instance to check
 * \param[in] node  Node where score would be applied
 *
 * \return true if \p rsc's promotion score should be considered on \p node,
 *         otherwise false
 */
static bool
promotion_score_applies(pe_resource_t *rsc, const pe_node_t *node)
{
    char *id = clone_strip(rsc->id);
    pe_resource_t *parent = uber_parent(rsc);
    pe_resource_t *active = NULL;
    const char *reason = "allowed";

    // Some checks apply only to anonymous clone instances
    if (!pcmk_is_set(rsc->flags, pe_rsc_unique)) {

        // If instance is active on the node, its score definitely applies
        active = find_active_anon_instance(parent, id, node);
        if (active == rsc) {
            reason = "active";
            goto check_allowed;
        }

        /* If *no* instance is active on this node, this instance's score will
         * count if it has been probed on this node.
         */
        if ((active == NULL) && anonymous_known_on(parent, id, node)) {
            reason = "probed";
            goto check_allowed;
        }
    }

    /* If this clone's status is unknown on *all* nodes (e.g. cluster startup),
     * take all instances' scores into account, to make sure we use any
     * permanent promotion scores.
     */
    if ((rsc->running_on == NULL) && (g_hash_table_size(rsc->known_on) == 0)) {
        reason = "none probed";
        goto check_allowed;
    }

    /* Otherwise, we've probed and/or started the resource *somewhere*, so
     * consider promotion scores on nodes where we know the status.
     */
    if ((pe_hash_table_lookup(rsc->known_on, node->details->id) != NULL)
        || (pe_find_node_id(rsc->running_on, node->details->id) != NULL)) {
        reason = "known";
    } else {
        pe_rsc_trace(rsc,
                     "Ignoring %s promotion score (for %s) on %s: not probed",
                     rsc->id, id, node->details->uname);
        free(id);
        return false;
    }

check_allowed:
    if (is_allowed(rsc, node)) {
        pe_rsc_trace(rsc, "Counting %s promotion score (for %s) on %s: %s",
                     rsc->id, id, node->details->uname, reason);
        free(id);
        return true;
    }

    pe_rsc_trace(rsc, "Ignoring %s promotion score (for %s) on %s: not allowed",
                 rsc->id, id, node->details->uname);
    free(id);
    return false;
}

/*!
 * \internal
 * \brief Get the value of a promotion score node attribute
 *
 * \param[in] rsc   Promotable clone instance to get promotion score for
 * \param[in] node  Node to get promotion score for
 * \param[in] name  Resource name to use in promotion score attribute name
 *
 * \return Value of promotion score node attribute for \p rsc on \p node
 */
static const char *
promotion_attr_value(pe_resource_t *rsc, const pe_node_t *node,
                     const char *name)
{
    char *attr_name = NULL;
    const char *attr_value = NULL;

    CRM_CHECK((rsc != NULL) && (node != NULL) && (name != NULL), return NULL);

    attr_name = pcmk_promotion_score_name(name);
    attr_value = pe_node_attribute_calculated(node, attr_name, rsc);
    free(attr_name);
    return attr_value;
}

/*!
 * \internal
 * \brief Get the promotion score for a clone instance on a node
 *
 * \param[in]  rsc         Promotable clone instance to get score for
 * \param[in]  node        Node to get score for
 * \param[out] is_default  If non-NULL, will be set true if no score available
 *
 * \return Promotion score for \p rsc on \p node (or 0 if none)
 */
static int
promotion_score(pe_resource_t *rsc, const pe_node_t *node, bool *is_default)
{
    char *name = NULL;
    const char *attr_value = NULL;

    if (is_default != NULL) {
        *is_default = true;
    }

    CRM_CHECK((rsc != NULL) && (node != NULL), return 0);

    /* If this is an instance of a cloned group, the promotion score is the sum
     * of all members' promotion scores.
     */
    if (rsc->children != NULL) {
        int score = 0;

        for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
            pe_resource_t *child = (pe_resource_t *) iter->data;
            bool child_default = false;
            int child_score = promotion_score(child, node, &child_default);

            if (!child_default && (is_default != NULL)) {
                *is_default = false;
            }
            score += child_score;
        }
        return score;
    }

    if (!promotion_score_applies(rsc, node)) {
        return 0;
    }

    /* For the promotion score attribute name, use the name the resource is
     * known as in resource history, since that's what crm_attribute --promotion
     * would have used.
     */
    name = (rsc->clone_name == NULL)? rsc->id : rsc->clone_name;

    attr_value = promotion_attr_value(rsc, node, name);
    if (attr_value != NULL) {
        pe_rsc_trace(rsc, "Promotion score for %s on %s = %s",
                     name, node->details->uname, pcmk__s(attr_value, "(unset)"));
    } else if (!pcmk_is_set(rsc->flags, pe_rsc_unique)) {
        /* If we don't have any resource history yet, we won't have clone_name.
         * In that case, for anonymous clones, try the resource name without
         * any instance number.
         */
        name = clone_strip(rsc->id);
        if (strcmp(rsc->id, name) != 0) {
            attr_value = promotion_attr_value(rsc, node, name);
            pe_rsc_trace(rsc, "Promotion score for %s on %s (for %s) = %s",
                         name, node->details->uname, rsc->id,
                         pcmk__s(attr_value, "(unset)"));
        }
        free(name);
    }

    if (attr_value == NULL) {
        return 0;
    }

    if (is_default != NULL) {
        *is_default = false;
    }
    return char2score(attr_value);
}

/*!
 * \internal
 * \brief Include promotion scores in instances' node weights and priorities
 *
 * \param[in] rsc  Promotable clone resource to update
 */
void
pcmk__add_promotion_scores(pe_resource_t *rsc)
{
    if (pe__set_clone_flag(rsc, pe__clone_promotion_added) == pcmk_rc_already) {
        return;
    }

    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) iter->data;

        GHashTableIter iter;
        pe_node_t *node = NULL;
        int score, new_score;

        g_hash_table_iter_init(&iter, child_rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **) &node)) {
            if (!pcmk__node_available(node, false, false)) {
                /* This node will never be promoted, so don't apply the
                 * promotion score, as that may lead to clone shuffling.
                 */
                continue;
            }

            score = promotion_score(child_rsc, node, NULL);
            if (score > 0) {
                new_score = pcmk__add_scores(node->weight, score);
                if (new_score != node->weight) {
                    pe_rsc_trace(rsc,
                                 "Adding promotion score to preference "
                                 "for %s on %s (%d->%d)",
                                 child_rsc->id, node->details->uname,
                                 node->weight, new_score);
                    node->weight = new_score;
                }
            }

            if (score > child_rsc->priority) {
                pe_rsc_trace(rsc,
                             "Updating %s priority to promotion score (%d->%d)",
                             child_rsc->id, child_rsc->priority, score);
                child_rsc->priority = score;
            }
        }
    }
}

/*!
 * \internal
 * \brief If a resource's current role is started, change it to unpromoted
 *
 * \param[in] data       Resource to update
 * \param[in] user_data  Ignored
 */
static void
set_current_role_unpromoted(void *data, void *user_data)
{
    pe_resource_t *rsc = (pe_resource_t *) data;

    if (rsc->role == RSC_ROLE_STARTED) {
        // Promotable clones should use unpromoted role instead of started
        rsc->role = RSC_ROLE_UNPROMOTED;
    }
    g_list_foreach(rsc->children, set_current_role_unpromoted, NULL);
}

/*!
 * \internal
 * \brief Set a resource's next role to unpromoted (or stopped if unassigned)
 *
 * \param[in] data       Resource to update
 * \param[in] user_data  Ignored
 */
static void
set_next_role_unpromoted(void *data, void *user_data)
{
    pe_resource_t *rsc = (pe_resource_t *) data;
    GList *assigned = NULL;

    rsc->fns->location(rsc, &assigned, FALSE);
    if (assigned == NULL) {
        pe__set_next_role(rsc, RSC_ROLE_STOPPED, "stopped instance");
    } else {
        pe__set_next_role(rsc, RSC_ROLE_UNPROMOTED, "unpromoted instance");
        g_list_free(assigned);
    }
    g_list_foreach(rsc->children, set_next_role_unpromoted, NULL);
}

/*!
 * \internal
 * \brief Set a resource's next role to promoted if not already set
 *
 * \param[in] data       Resource to update
 * \param[in] user_data  Ignored
 */
static void
set_next_role_promoted(void *data, gpointer user_data)
{
    pe_resource_t *rsc = (pe_resource_t *) data;

    if (rsc->next_role == RSC_ROLE_UNKNOWN) {
        pe__set_next_role(rsc, RSC_ROLE_PROMOTED, "promoted instance");
    }
    g_list_foreach(rsc->children, set_next_role_promoted, NULL);
}

/*!
 * \internal
 * \brief Show instance's promotion score on node where it will be active
 *
 * \param[in] instance  Promotable clone instance to show
 */
static void
show_promotion_score(pe_resource_t *instance)
{
    pe_node_t *chosen = instance->fns->location(instance, NULL, FALSE);

    if (pcmk_is_set(instance->cluster->flags, pe_flag_show_scores)
        && !pcmk__is_daemon && (instance->cluster->priv != NULL)) {

        pcmk__output_t *out = instance->cluster->priv;

        out->message(out, "promotion-score", instance, chosen,
                     pcmk_readable_score(instance->sort_index));
    } else {
        pe_rsc_debug(uber_parent(instance),
                     "%s promotion score on %s: sort=%s priority=%s",
                     instance->id,
                     ((chosen == NULL)? "none" : chosen->details->uname),
                     pcmk_readable_score(instance->sort_index),
                     pcmk_readable_score(instance->priority));
    }
}

/*!
 * \internal
 * \brief Set a clone instance's promotion priority
 *
 * \param[in] data       Promotable clone instance to update
 * \param[in] user_data  Instance's parent clone
 */
static void
set_instance_priority(gpointer data, gpointer user_data)
{
    pe_resource_t *instance = (pe_resource_t *) data;
    pe_resource_t *clone = (pe_resource_t *) user_data;
    pe_node_t *chosen = NULL;
    enum rsc_role_e next_role = RSC_ROLE_UNKNOWN;
    GList *list = NULL;

    pe_rsc_trace(clone, "Assigning priority for %s: %s", instance->id,
                 role2text(instance->next_role));

    if (instance->fns->state(instance, TRUE) == RSC_ROLE_STARTED) {
        set_current_role_unpromoted(instance, NULL);
    }

    // Only an instance that will be active can be promoted
    chosen = instance->fns->location(instance, &list, FALSE);
    if (pcmk__list_of_multiple(list)) {
        pcmk__config_err("Cannot promote non-colocated child %s",
                         instance->id);
    }
    g_list_free(list);
    if (chosen == NULL) {
        return;
    }

    next_role = instance->fns->state(instance, FALSE);
    switch (next_role) {
        case RSC_ROLE_STARTED:
        case RSC_ROLE_UNKNOWN:
            // Set instance priority to its promotion score (or -1 if none)
            {
                bool is_default = false;

                instance->priority = promotion_score(instance, chosen,
                                                      &is_default);
                if (is_default) {
                    /*
                     * Default to -1 if no value is set. This allows
                     * instances eligible for promotion to be specified
                     * based solely on rsc_location constraints, but
                     * prevents any instance from being promoted if neither
                     * a constraint nor a promotion score is present
                     */
                    instance->priority = -1;
                }
            }
            break;

        case RSC_ROLE_UNPROMOTED:
        case RSC_ROLE_STOPPED:
            // Instance can't be promoted
            instance->priority = -INFINITY;
            break;

        case RSC_ROLE_PROMOTED:
            // Nothing needed (re-creating actions after scheduling fencing)
            break;

        default:
            CRM_CHECK(FALSE, crm_err("Unknown resource role %d for %s",
                                     next_role, instance->id));
    }

    // Add relevant location constraint scores for promoted role
    apply_promoted_locations(instance, instance->rsc_location, chosen);
    apply_promoted_locations(instance, clone->rsc_location, chosen);

    // Apply relevant colocations with promoted role
    for (GList *iter = instance->rsc_cons; iter != NULL; iter = iter->next) {
        pcmk__colocation_t *cons = (pcmk__colocation_t *) iter->data;

        instance->cmds->rsc_colocation_lh(instance, cons->primary, cons,
                                          instance->cluster);
    }

    instance->sort_index = instance->priority;
    if (next_role == RSC_ROLE_PROMOTED) {
        instance->sort_index = INFINITY;
    }
    pe_rsc_trace(clone, "Assigning %s priority = %d",
                 instance->id, instance->priority);
}

/*!
 * \internal
 * \brief Set a promotable clone instance's role
 *
 * \param[in] data       Promotable clone instance to update
 * \param[in] user_data  Pointer to count of instances chosen for promotion
 */
static void
set_instance_role(gpointer data, gpointer user_data)
{
    pe_resource_t *instance = (pe_resource_t *) data;
    int *count = (int *) user_data;

    pe_resource_t *clone = uber_parent(instance);
    pe_node_t *chosen = NULL;

    show_promotion_score(instance);

    if (instance->sort_index < 0) {
        pe_rsc_trace(clone, "Not supposed to promote instance %s",
                     instance->id);

    } else if ((*count < pe__clone_promoted_max(instance))
               || !pcmk_is_set(clone->flags, pe_rsc_managed)) {
        chosen = node_to_be_promoted_on(instance);
    }

    if (chosen == NULL) {
        set_next_role_unpromoted(instance, NULL);
        return;
    }

    if ((instance->role < RSC_ROLE_PROMOTED)
        && !pcmk_is_set(instance->cluster->flags, pe_flag_have_quorum)
        && (instance->cluster->no_quorum_policy == no_quorum_freeze)) {
        crm_notice("Clone instance %s cannot be promoted without quorum",
                   instance->id);
        set_next_role_unpromoted(instance, NULL);
        return;
    }

    chosen->count++;
    pe_rsc_info(clone, "Choosing %s (%s) on %s for promotion",
                instance->id, role2text(instance->role),
                chosen->details->uname);
    set_next_role_promoted(instance, NULL);
    (*count)++;
}

/*!
 * \internal
 * \brief Set roles for all instances of a promotable clone
 *
 * \param[in] clone  Promotable clone resource to update
 */
void
pcmk__set_instance_roles(pe_resource_t *rsc)
{
    int promoted = 0;
    GHashTableIter iter;
    pe_node_t *node = NULL;

    // Repurpose count to track the number of promoted instances allocated
    g_hash_table_iter_init(&iter, rsc->allowed_nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
        node->count = 0;
    }

    // Set instances' promotion priorities and sort by highest priority first
    g_list_foreach(rsc->children, set_instance_priority, rsc);
    sort_promotable_instances(rsc);

    // Choose the first N eligible instances to be promoted
    g_list_foreach(rsc->children, set_instance_role, &promoted);
    pe_rsc_info(rsc, "%s: Promoted %d instances of a possible %d",
                rsc->id, promoted, pe__clone_promoted_max(rsc));
}

void
create_promotable_actions(pe_resource_t * rsc, pe_working_set_t * data_set)
{
    pe_action_t *action = NULL;
    GList *gIter = rsc->children;
    pe_action_t *action_complete = NULL;
    bool any_promoting = false;
    bool any_demoting = false;

    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    pe_rsc_debug(rsc, "Creating actions for %s", rsc->id);

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        pe_rsc_trace(rsc, "Creating actions for %s", child_rsc->id);
        child_rsc->cmds->create_actions(child_rsc, data_set);
        check_for_role_change(child_rsc, &any_demoting, &any_promoting);
    }

    /* promote */
    action = pe__new_rsc_pseudo_action(rsc, RSC_PROMOTE, !any_promoting, true);
    action_complete = pe__new_rsc_pseudo_action(rsc, RSC_PROMOTED,
                                                !any_promoting, true);
    action_complete->priority = INFINITY;

    if (clone_data->promote_notify == NULL) {
        clone_data->promote_notify = pe__clone_notif_pseudo_ops(rsc,
                                                                RSC_PROMOTE,
                                                                action,
                                                                action_complete);
    }

    /* demote */
    action = pe__new_rsc_pseudo_action(rsc, RSC_DEMOTE, !any_demoting, true);
    action_complete = pe__new_rsc_pseudo_action(rsc, RSC_DEMOTED, !any_demoting,
                                                true);
    action_complete->priority = INFINITY;

    if (clone_data->demote_notify == NULL) {
        clone_data->demote_notify = pe__clone_notif_pseudo_ops(rsc, RSC_DEMOTE,
                                                               action,
                                                               action_complete);

        if (clone_data->promote_notify) {
            /* If we ever wanted groups to have notifications we'd need to move this to native_internal_constraints() one day
             * Requires exposing *_notify
             */
            order_actions(clone_data->stop_notify->post_done, clone_data->promote_notify->pre,
                          pe_order_optional);
            order_actions(clone_data->start_notify->post_done, clone_data->promote_notify->pre,
                          pe_order_optional);
            order_actions(clone_data->demote_notify->post_done, clone_data->promote_notify->pre,
                          pe_order_optional);
            order_actions(clone_data->demote_notify->post_done, clone_data->start_notify->pre,
                          pe_order_optional);
            order_actions(clone_data->demote_notify->post_done, clone_data->stop_notify->pre,
                          pe_order_optional);
        }
    }

    /* restore the correct priority */

    gIter = rsc->children;
    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->priority = rsc->priority;
    }
}

void
promote_demote_constraints(pe_resource_t *rsc, pe_working_set_t *data_set)
{
    /* global stopped before start */
    pcmk__order_resource_actions(rsc, RSC_STOPPED, rsc, RSC_START,
                                 pe_order_optional, data_set);

    /* global stopped before promote */
    pcmk__order_resource_actions(rsc, RSC_STOPPED, rsc, RSC_PROMOTE,
                                 pe_order_optional, data_set);

    /* global demoted before start */
    pcmk__order_resource_actions(rsc, RSC_DEMOTED, rsc, RSC_START,
                                 pe_order_optional, data_set);

    /* global started before promote */
    pcmk__order_resource_actions(rsc, RSC_STARTED, rsc, RSC_PROMOTE,
                                 pe_order_optional, data_set);

    /* global demoted before stop */
    pcmk__order_resource_actions(rsc, RSC_DEMOTED, rsc, RSC_STOP,
                                 pe_order_optional, data_set);

    /* global demote before demoted */
    pcmk__order_resource_actions(rsc, RSC_DEMOTE, rsc, RSC_DEMOTED,
                                 pe_order_optional, data_set);

    /* global demoted before promote */
    pcmk__order_resource_actions(rsc, RSC_DEMOTED, rsc, RSC_PROMOTE,
                                 pe_order_optional, data_set);
}


void
promotable_constraints(pe_resource_t * rsc, pe_working_set_t * data_set)
{
    GList *gIter = rsc->children;
    pe_resource_t *last_rsc = NULL;

    promote_demote_constraints(rsc, data_set);

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        /* child demote before promote */
        pcmk__order_resource_actions(child_rsc, RSC_DEMOTE, child_rsc,
                                     RSC_PROMOTE, pe_order_optional, data_set);

        order_instance_promotion(rsc, child_rsc, last_rsc);
        order_instance_demotion(rsc, child_rsc, last_rsc);

        last_rsc = child_rsc;
    }
}

static void
node_hash_update_one(GHashTable * hash, pe_node_t * other, const char *attr, int score)
{
    GHashTableIter iter;
    pe_node_t *node = NULL;
    const char *value = NULL;

    if (other == NULL) {
        return;

    } else if (attr == NULL) {
        attr = CRM_ATTR_UNAME;
    }
 
    value = pe_node_attribute_raw(other, attr);
    g_hash_table_iter_init(&iter, hash);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
        const char *tmp = pe_node_attribute_raw(node, attr);

        if (pcmk__str_eq(value, tmp, pcmk__str_casei)) {
            crm_trace("%s: %d + %d", node->details->uname, node->weight, other->weight);
            node->weight = pcmk__add_scores(node->weight, score);
        }
    }
}

void
promotable_colocation_rh(pe_resource_t *dependent, pe_resource_t *primary,
                         pcmk__colocation_t *constraint,
                         pe_working_set_t *data_set)
{
    GList *gIter = NULL;

    if (pcmk_is_set(dependent->flags, pe_rsc_provisional)) {
        GList *affected_nodes = NULL;

        for (gIter = primary->children; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;
            pe_node_t *chosen = child_rsc->fns->location(child_rsc, NULL, FALSE);
            enum rsc_role_e next_role = child_rsc->fns->state(child_rsc, FALSE);

            pe_rsc_trace(primary, "Processing: %s", child_rsc->id);
            if ((chosen != NULL) && (next_role == constraint->primary_role)) {
                pe_rsc_trace(primary, "Applying: %s %s %s %d", child_rsc->id,
                             role2text(next_role), chosen->details->uname, constraint->score);
                if (constraint->score < INFINITY) {
                    node_hash_update_one(dependent->allowed_nodes, chosen,
                                         constraint->node_attribute, constraint->score);
                }
                affected_nodes = g_list_prepend(affected_nodes, chosen);
            }
        }

        /* Only do this if it's not a promoted-with-promoted colocation. Doing
         * this unconditionally would prevent unpromoted instances from being
         * started.
         */
        if ((constraint->dependent_role != RSC_ROLE_PROMOTED)
            || (constraint->primary_role != RSC_ROLE_PROMOTED)) {

            if (constraint->score >= INFINITY) {
                node_list_exclude(dependent->allowed_nodes, affected_nodes,
                                  TRUE);
            }
        }
        g_list_free(affected_nodes);

    } else if (constraint->dependent_role == RSC_ROLE_PROMOTED) {
        pe_resource_t *primary_instance;

        primary_instance = find_compatible_child(dependent, primary,
                                                 constraint->primary_role,
                                                 FALSE, data_set);
        if ((primary_instance == NULL) && (constraint->score >= INFINITY)) {
            pe_rsc_trace(dependent, "%s can't be promoted %s",
                         dependent->id, constraint->id);
            dependent->priority = -INFINITY;

        } else if (primary_instance != NULL) {
            int new_priority = pcmk__add_scores(dependent->priority,
                                                constraint->score);

            pe_rsc_debug(dependent, "Applying %s to %s",
                         constraint->id, dependent->id);
            pe_rsc_debug(dependent, "\t%s: %d->%d",
                         dependent->id, dependent->priority, new_priority);
            dependent->priority = new_priority;
        }
    }

    return;
}

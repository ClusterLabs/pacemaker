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

static void
child_demoting_constraints(pe_resource_t *rsc, pe_resource_t *child,
                           pe_resource_t *last)
{

    /* child demote before global demoted */
    pcmk__order_resource_actions(child, RSC_DEMOTE, rsc, RSC_DEMOTED,
                                 pe_order_implies_then_printed, rsc->cluster);

    /* global demote before child demote */
    pcmk__order_resource_actions(rsc, RSC_DEMOTE, child, RSC_DEMOTE,
                                 pe_order_implies_first_printed, rsc->cluster);

    if (!pe__clone_is_ordered(rsc)) {
        pe_rsc_trace(rsc, "Un-ordered version");

    } else if (last == NULL) {
        pe_rsc_trace(rsc, "Ordered version (1st node)");
        /* first child stop before global stopped */
        pcmk__order_resource_actions(child, RSC_DEMOTE, rsc, RSC_DEMOTED, pe_order_optional,
                                     rsc->cluster);

    } else {
        pe_rsc_trace(rsc, "Ordered version");

        /* child/child relative demote */
        pcmk__order_resource_actions(child, RSC_DEMOTE, last, RSC_DEMOTE, pe_order_optional,
                                     rsc->cluster);
    }
}

static void
check_promotable_actions(pe_resource_t *rsc, gboolean *demoting,
                         gboolean *promoting)
{
    GList *gIter = NULL;

    if (rsc->children) {
        gIter = rsc->children;
        for (; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child = (pe_resource_t *) gIter->data;

            check_promotable_actions(child, demoting, promoting);
        }
        return;
    }

    CRM_ASSERT(demoting != NULL);
    CRM_ASSERT(promoting != NULL);

    gIter = rsc->actions;
    for (; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

        if (*promoting && *demoting) {
            return;

        } else if (pcmk_is_set(action->flags, pe_action_optional)) {
            continue;

        } else if (pcmk__str_eq(RSC_DEMOTE, action->task, pcmk__str_casei)) {
            *demoting = TRUE;

        } else if (pcmk__str_eq(RSC_PROMOTE, action->task, pcmk__str_casei)) {
            *promoting = TRUE;
        }
    }
}

static void
apply_promoted_location(pe_resource_t *child, GList *location_constraints,
                        pe_node_t *chosen)
{
    CRM_CHECK(child && chosen, return);
    for (GList *gIter = location_constraints; gIter; gIter = gIter->next) {
        pe_node_t *cons_node = NULL;
        pe__location_t *cons = gIter->data;

        if (cons->role_filter == RSC_ROLE_PROMOTED) {
            pe_rsc_trace(child, "Applying %s to %s", cons->id, child->id);
            cons_node = pe_find_node_id(cons->node_list_rh, chosen->details->id);
        }
        if (cons_node != NULL) {
            int new_priority = pcmk__add_scores(child->priority,
                                                cons_node->weight);

            pe_rsc_trace(child, "\t%s[%s]: %d -> %d (%d)",
                         child->id, cons_node->details->uname, child->priority,
                         new_priority, cons_node->weight);
            child->priority = new_priority;
        }
    }
}

static pe_node_t *
guest_location(pe_node_t *guest_node)
{
    pe_resource_t *guest = guest_node->details->remote_rsc->container;

    return guest->fns->location(guest, NULL, FALSE);
}

static pe_node_t *
node_to_be_promoted_on(pe_resource_t *rsc)
{
    pe_node_t *node = NULL;
    pe_node_t *local_node = NULL;
    pe_resource_t *parent = uber_parent(rsc);
    clone_variant_data_t *clone_data = NULL;

#if 0
    enum rsc_role_e role = RSC_ROLE_UNKNOWN;

    role = rsc->fns->state(rsc, FALSE);
    crm_info("%s role: %s", rsc->id, role2text(role));
#endif

    if (rsc->children) {
        GList *gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child = (pe_resource_t *) gIter->data;

            if (node_to_be_promoted_on(child) == NULL) {
                pe_rsc_trace(rsc, "Child %s of %s can't be promoted", child->id, rsc->id);
                return NULL;
            }
        }
    }

    node = rsc->fns->location(rsc, NULL, FALSE);
    if (node == NULL) {
        pe_rsc_trace(rsc, "%s cannot be promoted: not allocated", rsc->id);
        return NULL;

    } else if (!pcmk_is_set(rsc->flags, pe_rsc_managed)) {
        if (rsc->fns->state(rsc, TRUE) == RSC_ROLE_PROMOTED) {
            crm_notice("Forcing unmanaged instance %s to remain promoted on %s",
                       rsc->id, node->details->uname);

        } else {
            return NULL;
        }

    } else if (rsc->priority < 0) {
        pe_rsc_trace(rsc, "%s cannot be promoted: preference: %d",
                     rsc->id, rsc->priority);
        return NULL;

    } else if (!pcmk__node_available(node)) {
        crm_trace("Node can't run any resources: %s", node->details->uname);
        return NULL;

    /* @TODO It's possible this check should be done in pcmk__node_available()
     * instead. We should investigate all its callers to figure out whether that
     * would be a good idea.
     */
    } else if (pe__is_guest_node(node) && (guest_location(node) == NULL)) {
        pe_rsc_trace(rsc, "%s cannot be promoted: guest %s not allocated",
                     rsc->id, node->details->remote_rsc->container->id);
        return NULL;
    }

    get_clone_variant_data(clone_data, parent);
    local_node = pe_hash_table_lookup(parent->allowed_nodes, node->details->id);

    if (local_node == NULL) {
        crm_err("%s cannot run on %s: node not allowed", rsc->id, node->details->uname);
        return NULL;

    } else if ((local_node->count < clone_data->promoted_node_max)
               || !pcmk_is_set(rsc->flags, pe_rsc_managed)) {
        return local_node;

    } else {
        pe_rsc_trace(rsc, "%s cannot be promoted on %s: node full",
                     rsc->id, node->details->uname);
    }

    return NULL;
}

static gint
sort_promotable_instance(gconstpointer a, gconstpointer b, gpointer data_set)
{
    int rc;
    enum rsc_role_e role1 = RSC_ROLE_UNKNOWN;
    enum rsc_role_e role2 = RSC_ROLE_UNKNOWN;

    const pe_resource_t *resource1 = (const pe_resource_t *)a;
    const pe_resource_t *resource2 = (const pe_resource_t *)b;

    CRM_ASSERT(resource1 != NULL);
    CRM_ASSERT(resource2 != NULL);

    role1 = resource1->fns->state(resource1, TRUE);
    role2 = resource2->fns->state(resource2, TRUE);

    rc = sort_rsc_index(a, b);
    if (rc != 0) {
        crm_trace("%s %c %s (index)", resource1->id, rc < 0 ? '<' : '>', resource2->id);
        return rc;
    }

    if (role1 > role2) {
        crm_trace("%s %c %s (role)", resource1->id, '<', resource2->id);
        return -1;

    } else if (role1 < role2) {
        crm_trace("%s %c %s (role)", resource1->id, '>', resource2->id);
        return 1;
    }

    return pcmk__cmp_instance(a, b);
}

static void
promotion_order(pe_resource_t *rsc, pe_working_set_t *data_set)
{
    GList *gIter = NULL;
    pe_node_t *node = NULL;
    pe_node_t *chosen = NULL;
    char score[33];
    size_t len = sizeof(score);

    if (pe__set_clone_flag(rsc, pe__clone_promotion_constrained)
            == pcmk_rc_already) {
        return;
    }
    pe_rsc_trace(rsc, "Merging weights for %s", rsc->id);
    pe__set_resource_flags(rsc, pe_rsc_merging);

    for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child = (pe_resource_t *) gIter->data;

        pe_rsc_trace(rsc, "Sort index: %s = %d", child->id, child->sort_index);
    }
    pe__show_node_weights(true, rsc, "Before", rsc->allowed_nodes, data_set);

    gIter = rsc->children;
    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child = (pe_resource_t *) gIter->data;

        chosen = child->fns->location(child, NULL, FALSE);
        if (chosen == NULL || child->sort_index < 0) {
            pe_rsc_trace(rsc, "Skipping %s", child->id);
            continue;
        }

        node = (pe_node_t *) pe_hash_table_lookup(rsc->allowed_nodes, chosen->details->id);
        CRM_ASSERT(node != NULL);
        // Add promotion preferences and rsc_location scores when role=Promoted
        score2char_stack(child->sort_index, score, len);
        pe_rsc_trace(rsc, "Adding %s to %s from %s", score,
                     node->details->uname, child->id);
        node->weight = pcmk__add_scores(child->sort_index, node->weight);
    }

    pe__show_node_weights(true, rsc, "Middle", rsc->allowed_nodes, data_set);

    gIter = rsc->rsc_cons;
    for (; gIter != NULL; gIter = gIter->next) {
        pcmk__colocation_t *constraint = (pcmk__colocation_t *) gIter->data;

        /* (Re-)add location preferences of resources that a promoted instance
         * should/must be colocated with.
         */
        if (constraint->dependent_role == RSC_ROLE_PROMOTED) {
            enum pe_weights flags = constraint->score == INFINITY ? 0 : pe_weights_rollback;

            pe_rsc_trace(rsc, "RHS: %s with %s: %d",
                         constraint->dependent->id, constraint->primary->id,
                         constraint->score);
            rsc->allowed_nodes = constraint->primary->cmds->merge_weights(
                constraint->primary, rsc->id, rsc->allowed_nodes,
                constraint->node_attribute,
                constraint->score / (float) INFINITY, flags);
        }
    }

    gIter = rsc->rsc_cons_lhs;
    for (; gIter != NULL; gIter = gIter->next) {
        pcmk__colocation_t *constraint = (pcmk__colocation_t *) gIter->data;

        if (!pcmk__colocation_has_influence(constraint, NULL)) {
            continue;
        }

        /* (Re-)add location preferences of resources that wish to be colocated
         * with a promoted instance.
         */
        if (constraint->primary_role == RSC_ROLE_PROMOTED) {
            pe_rsc_trace(rsc, "LHS: %s with %s: %d",
                         constraint->dependent->id, constraint->primary->id,
                         constraint->score);
            rsc->allowed_nodes = constraint->dependent->cmds->merge_weights(
                constraint->dependent, rsc->id, rsc->allowed_nodes,
                constraint->node_attribute,
                constraint->score / (float) INFINITY,
                pe_weights_rollback|pe_weights_positive);
        }
    }

    // Ban resource from all nodes if it needs a ticket but doesn't have it
    pcmk__require_promotion_tickets(rsc);

    pe__show_node_weights(true, rsc, "After", rsc->allowed_nodes, data_set);

    /* write them back and sort */

    gIter = rsc->children;
    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child = (pe_resource_t *) gIter->data;

        chosen = child->fns->location(child, NULL, FALSE);
        if (!pcmk_is_set(child->flags, pe_rsc_managed)
            && (child->next_role == RSC_ROLE_PROMOTED)) {
            child->sort_index = INFINITY;

        } else if (chosen == NULL || child->sort_index < 0) {
            pe_rsc_trace(rsc, "%s: %d", child->id, child->sort_index);

        } else {
            node = (pe_node_t *) pe_hash_table_lookup(rsc->allowed_nodes, chosen->details->id);
            CRM_ASSERT(node != NULL);

            child->sort_index = node->weight;
        }
        pe_rsc_trace(rsc, "Set sort index: %s = %d", child->id, child->sort_index);
    }

    rsc->children = g_list_sort_with_data(rsc->children,
                                          sort_promotable_instance, data_set);
    pe__clear_resource_flags(rsc, pe_rsc_merging);
}

static gboolean
filter_anonymous_instance(pe_resource_t *rsc, const pe_node_t *node)
{
    GList *rIter = NULL;
    char *key = clone_strip(rsc->id);
    pe_resource_t *parent = uber_parent(rsc);

    for (rIter = parent->children; rIter; rIter = rIter->next) {
        /* If there is an active instance on the node, only it receives the
         * promotion score. Use ->find_rsc() in case this is a cloned group.
         */
        pe_resource_t *child = rIter->data;
        pe_resource_t *active = parent->fns->find_rsc(child, key, node, pe_find_clone|pe_find_current);

        if(rsc == active) {
            pe_rsc_trace(rsc, "Found %s for %s active on %s: done", active->id, key, node->details->uname);
            free(key);
            return TRUE;
        } else if(active) {
            pe_rsc_trace(rsc, "Found %s for %s on %s: not %s", active->id, key, node->details->uname, rsc->id);
            free(key);
            return FALSE;
        } else {
            pe_rsc_trace(rsc, "%s on %s: not active", key, node->details->uname);
        }
    }

    for (rIter = parent->children; rIter; rIter = rIter->next) {
        pe_resource_t *child = rIter->data;

        /*
         * We know it's not running, but any score will still count if
         * the instance has been probed on $node
         *
         * Again use ->find_rsc() because we might be a cloned group
         * and knowing that other members of the group are known here
         * implies nothing
         */
        rsc = parent->fns->find_rsc(child, key, NULL, pe_find_clone);
        CRM_LOG_ASSERT(rsc);
        if(rsc) {
            pe_rsc_trace(rsc, "Checking %s for %s on %s", rsc->id, key, node->details->uname);
            if (g_hash_table_lookup(rsc->known_on, node->details->id)) {
                free(key);
                return TRUE;
            }
        }
    }
    free(key);
    return FALSE;
}

static const char *
lookup_promotion_score(pe_resource_t *rsc, const pe_node_t *node, const char *name)
{
    const char *attr_value = NULL;

    if (node && name) {
        char *attr_name = pcmk_promotion_score_name(name);

        attr_value = pe_node_attribute_calculated(node, attr_name, rsc);
        free(attr_name);
    }
    return attr_value;
}

static int
promotion_score(pe_resource_t *rsc, const pe_node_t *node, int not_set_value)
{
    char *name = rsc->id;
    const char *attr_value = NULL;
    int score = not_set_value;
    pe_node_t *match = NULL;

    CRM_CHECK(node != NULL, return not_set_value);

    if (rsc->children) {
        GList *gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child = (pe_resource_t *) gIter->data;
            int c_score = promotion_score(child, node, not_set_value);

            if (score == not_set_value) {
                score = c_score;
            } else {
                score += c_score;
            }
        }
        return score;
    }

    if (!pcmk_is_set(rsc->flags, pe_rsc_unique)
        && filter_anonymous_instance(rsc, node)) {

        pe_rsc_trace(rsc, "Anonymous clone %s is allowed on %s", rsc->id, node->details->uname);

    } else if (rsc->running_on || g_hash_table_size(rsc->known_on)) {
        /* If we've probed and/or started the resource anywhere, consider
         * promotion scores only from nodes where we know the status. However,
         * if the status of all nodes is unknown (e.g. cluster startup),
         * skip this code, to make sure we take into account any permanent
         * promotion scores set previously.
         */
        pe_node_t *known = pe_hash_table_lookup(rsc->known_on, node->details->id);

        match = pe_find_node_id(rsc->running_on, node->details->id);
        if ((match == NULL) && (known == NULL)) {
            pe_rsc_trace(rsc, "skipping %s (aka. %s) promotion score on %s because inactive",
                         rsc->id, rsc->clone_name, node->details->uname);
            return score;
        }
    }

    match = pe_hash_table_lookup(rsc->allowed_nodes, node->details->id);
    if (match == NULL) {
        return score;

    } else if (match->weight < 0) {
        pe_rsc_trace(rsc, "%s on %s has score: %d - ignoring",
                     rsc->id, match->details->uname, match->weight);
        return score;
    }

    if (rsc->clone_name) {
        /* Use the name the lrm knows this resource as,
         * since that's what crm_attribute --promotion would have used
         */
        name = rsc->clone_name;
    }

    attr_value = lookup_promotion_score(rsc, node, name);
    pe_rsc_trace(rsc, "Promotion score for %s on %s = %s",
                 name, node->details->uname, pcmk__s(attr_value, "(unset)"));

    if ((attr_value == NULL) && !pcmk_is_set(rsc->flags, pe_rsc_unique)) {
        /* If we don't have any LRM history yet, we won't have clone_name -- in
         * that case, for anonymous clones, try the resource name without any
         * instance number.
         */
        name = clone_strip(rsc->id);
        if (strcmp(rsc->id, name)) {
            attr_value = lookup_promotion_score(rsc, node, name);
            pe_rsc_trace(rsc, "Stripped promotion score for %s on %s = %s",
                         name, node->details->uname,
                         pcmk__s(attr_value, "(unset)"));
        }
        free(name);
    }

    if (attr_value != NULL) {
        score = char2score(attr_value);
    }

    return score;
}

void
pcmk__add_promotion_scores(pe_resource_t *rsc)
{
    int score, new_score;
    GList *gIter = rsc->children;

    if (pe__set_clone_flag(rsc, pe__clone_promotion_added) == pcmk_rc_already) {
        return;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        GHashTableIter iter;
        pe_node_t *node = NULL;
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        g_hash_table_iter_init(&iter, child_rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
            if (!pcmk__node_available(node)) {
                /* This node will never be promoted, so don't apply the
                 * promotion score, as that may lead to clone shuffling.
                 */
                continue;
            }

            score = promotion_score(child_rsc, node, 0);
            if (score > 0) {
                new_score = pcmk__add_scores(node->weight, score);
                if (new_score != node->weight) {
                    pe_rsc_trace(rsc, "\t%s: Updating preference for %s (%d->%d)",
                                 child_rsc->id, node->details->uname, node->weight, new_score);
                    node->weight = new_score;
                }
            }

            new_score = QB_MAX(child_rsc->priority, score);
            if (new_score != child_rsc->priority) {
                pe_rsc_trace(rsc, "\t%s: Updating priority (%d->%d)",
                             child_rsc->id, child_rsc->priority, new_score);
                child_rsc->priority = new_score;
            }
        }
    }
}

static void
set_role_unpromoted(pe_resource_t *rsc, bool current)
{
    GList *gIter = rsc->children;

    if (current) {
        if (rsc->role == RSC_ROLE_STARTED) {
            rsc->role = RSC_ROLE_UNPROMOTED;
        }

    } else {
        GList *allocated = NULL;

        rsc->fns->location(rsc, &allocated, FALSE);
        pe__set_next_role(rsc, (allocated? RSC_ROLE_UNPROMOTED : RSC_ROLE_STOPPED),
                          "unpromoted instance");
        g_list_free(allocated);
    }

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        set_role_unpromoted(child_rsc, current);
    }
}

static void
set_role_promoted(pe_resource_t *rsc, gpointer user_data)
{
    if (rsc->next_role == RSC_ROLE_UNKNOWN) {
        pe__set_next_role(rsc, RSC_ROLE_PROMOTED, "promoted instance");
    }

    g_list_foreach(rsc->children, (GFunc) set_role_promoted, NULL);
}

pe_node_t *
pcmk__set_instance_roles(pe_resource_t *rsc, pe_working_set_t *data_set)
{
    int promoted = 0;
    GList *gIter = NULL;
    GList *gIter2 = NULL;
    GHashTableIter iter;
    pe_node_t *node = NULL;
    pe_node_t *chosen = NULL;
    enum rsc_role_e next_role = RSC_ROLE_UNKNOWN;
    char score[33];
    size_t len = sizeof(score);
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    // Repurpose count to track the number of promoted instances allocated
    g_hash_table_iter_init(&iter, rsc->allowed_nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
        node->count = 0;
    }

    /*
     * assign priority
     */
    for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        GList *list = NULL;
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        pe_rsc_trace(rsc, "Assigning priority for %s: %s", child_rsc->id,
                     role2text(child_rsc->next_role));

        if (child_rsc->fns->state(child_rsc, TRUE) == RSC_ROLE_STARTED) {
            set_role_unpromoted(child_rsc, true);
        }

        chosen = child_rsc->fns->location(child_rsc, &list, FALSE);
        if (pcmk__list_of_multiple(list)) {
            pcmk__config_err("Cannot promote non-colocated child %s",
                             child_rsc->id);
        }

        g_list_free(list);
        if (chosen == NULL) {
            continue;
        }

        next_role = child_rsc->fns->state(child_rsc, FALSE);
        switch (next_role) {
            case RSC_ROLE_STARTED:
            case RSC_ROLE_UNKNOWN:
                /*
                 * Default to -1 if no value is set
                 *
                 * This allows instances eligible for promotion to be specified
                 * based solely on rsc_location constraints,
                 * but prevents anyone from being promoted if
                 * neither a constraint nor a promotion score is present
                 */
                child_rsc->priority = promotion_score(child_rsc, chosen, -1);
                break;

            case RSC_ROLE_UNPROMOTED:
            case RSC_ROLE_STOPPED:
                child_rsc->priority = -INFINITY;
                break;
            case RSC_ROLE_PROMOTED:
                /* We will arrive here if we're re-creating actions after a stonith
                 */
                break;
            default:
                CRM_CHECK(FALSE /* unhandled */ ,
                          crm_err("Unknown resource role: %d for %s", next_role, child_rsc->id));
        }

        apply_promoted_location(child_rsc, child_rsc->rsc_location, chosen);
        apply_promoted_location(child_rsc, rsc->rsc_location, chosen);

        for (gIter2 = child_rsc->rsc_cons; gIter2 != NULL; gIter2 = gIter2->next) {
            pcmk__colocation_t *cons = (pcmk__colocation_t *) gIter2->data;

            child_rsc->cmds->rsc_colocation_lh(child_rsc, cons->primary, cons,
                                               data_set);
        }

        child_rsc->sort_index = child_rsc->priority;
        pe_rsc_trace(rsc, "Assigning priority for %s: %d", child_rsc->id, child_rsc->priority);

        if (next_role == RSC_ROLE_PROMOTED) {
            child_rsc->sort_index = INFINITY;
        }
    }

    pe__show_node_weights(true, rsc, "Pre merge", rsc->allowed_nodes, data_set);
    promotion_order(rsc, data_set);

    // Choose the first N eligible instances to be promoted
    for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;
        score2char_stack(child_rsc->sort_index, score, len);

        chosen = child_rsc->fns->location(child_rsc, NULL, FALSE);
        if (pcmk_is_set(data_set->flags, pe_flag_show_scores) && !pcmk__is_daemon) {
            if (data_set->priv != NULL) {
                pcmk__output_t *out = data_set->priv;
                out->message(out, "promotion-score", child_rsc, chosen, score);
            }

        } else {
            pe_rsc_trace(rsc, "%s promotion score on %s: %s", child_rsc->id,
                         (chosen? chosen->details->uname : "none"), score);
        }

        chosen = NULL;          /* nuke 'chosen' so that we don't promote more than the
                                 * required number of instances
                                 */

        if (child_rsc->sort_index < 0) {
            pe_rsc_trace(rsc, "Not supposed to promote child: %s", child_rsc->id);

        } else if ((promoted < clone_data->promoted_max)
                   || !pcmk_is_set(rsc->flags, pe_rsc_managed)) {
            chosen = node_to_be_promoted_on(child_rsc);
        }

        pe_rsc_debug(rsc, "%s promotion score: %d", child_rsc->id, child_rsc->priority);

        if (chosen == NULL) {
            set_role_unpromoted(child_rsc, false);
            continue;

        } else if ((child_rsc->role < RSC_ROLE_PROMOTED)
              && !pcmk_is_set(data_set->flags, pe_flag_have_quorum)
              && data_set->no_quorum_policy == no_quorum_freeze) {
            crm_notice("Resource %s cannot be elevated from %s to %s: no-quorum-policy=freeze",
                       child_rsc->id, role2text(child_rsc->role), role2text(child_rsc->next_role));
            set_role_unpromoted(child_rsc, false);
            continue;
        }

        chosen->count++;
        pe_rsc_info(rsc, "Promoting %s (%s %s)",
                    child_rsc->id, role2text(child_rsc->role), chosen->details->uname);
        set_role_promoted(child_rsc, NULL);
        promoted++;
    }

    pe_rsc_info(rsc, "%s: Promoted %d instances of a possible %d",
                rsc->id, promoted, clone_data->promoted_max);

    return NULL;
}

void
create_promotable_actions(pe_resource_t * rsc, pe_working_set_t * data_set)
{
    pe_action_t *action = NULL;
    GList *gIter = rsc->children;
    pe_action_t *action_complete = NULL;
    gboolean any_promoting = FALSE;
    gboolean any_demoting = FALSE;

    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    pe_rsc_debug(rsc, "Creating actions for %s", rsc->id);

    for (; gIter != NULL; gIter = gIter->next) {
        gboolean child_promoting = FALSE;
        gboolean child_demoting = FALSE;
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        pe_rsc_trace(rsc, "Creating actions for %s", child_rsc->id);
        child_rsc->cmds->create_actions(child_rsc, data_set);
        check_promotable_actions(child_rsc, &child_demoting, &child_promoting);

        any_demoting = any_demoting || child_demoting;
        any_promoting = any_promoting || child_promoting;
        pe_rsc_trace(rsc, "Created actions for %s: %d %d", child_rsc->id, child_promoting,
                     child_demoting);
    }

    /* promote */
    action = pcmk__new_rsc_pseudo_action(rsc, RSC_PROMOTE, !any_promoting,
                                         true);
    action_complete = pcmk__new_rsc_pseudo_action(rsc, RSC_PROMOTED,
                                                  !any_promoting, true);
    action_complete->priority = INFINITY;

    if (clone_data->promote_notify == NULL) {
        clone_data->promote_notify = pcmk__clone_notif_pseudo_ops(rsc,
                                                                  RSC_PROMOTE,
                                                                  action,
                                                                  action_complete);
    }

    /* demote */
    action = pcmk__new_rsc_pseudo_action(rsc, RSC_DEMOTE, !any_demoting, true);
    action_complete = pcmk__new_rsc_pseudo_action(rsc, RSC_DEMOTED,
                                                  !any_demoting, true);
    action_complete->priority = INFINITY;

    if (clone_data->demote_notify == NULL) {
        clone_data->demote_notify = pcmk__clone_notif_pseudo_ops(rsc,
                                                                 RSC_DEMOTE,
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
        child_demoting_constraints(rsc, child_rsc, last_rsc);

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

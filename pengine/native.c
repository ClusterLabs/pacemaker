/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <pengine.h>
#include <crm/pengine/rules.h>
#include <crm/msg_xml.h>
#include <allocate.h>
#include <utils.h>

/* #define DELETE_THEN_REFRESH 1  // The crmd will remove the resource from the CIB itself, making this redundant */
#define INFINITY_HACK   (INFINITY * -100)

#define VARIANT_NATIVE 1
#include <lib/pengine/variant.h>

void native_rsc_colocation_rh_must(resource_t * rsc_lh, gboolean update_lh,
                                   resource_t * rsc_rh, gboolean update_rh);

void native_rsc_colocation_rh_mustnot(resource_t * rsc_lh, gboolean update_lh,
                                      resource_t * rsc_rh, gboolean update_rh);

void Recurring(resource_t * rsc, action_t * start, node_t * node, pe_working_set_t * data_set);
void RecurringOp(resource_t * rsc, action_t * start, node_t * node,
                 xmlNode * operation, pe_working_set_t * data_set);
void Recurring_Stopped(resource_t * rsc, action_t * start, node_t * node,
                       pe_working_set_t * data_set);
void RecurringOp_Stopped(resource_t * rsc, action_t * start, node_t * node,
                         xmlNode * operation, pe_working_set_t * data_set);
void pe_post_notify(resource_t * rsc, node_t * node, action_t * op,
                    notify_data_t * n_data, pe_working_set_t * data_set);

gboolean DeleteRsc(resource_t * rsc, node_t * node, gboolean optional, pe_working_set_t * data_set);
gboolean StopRsc(resource_t * rsc, node_t * next, gboolean optional, pe_working_set_t * data_set);
gboolean StartRsc(resource_t * rsc, node_t * next, gboolean optional, pe_working_set_t * data_set);
gboolean DemoteRsc(resource_t * rsc, node_t * next, gboolean optional, pe_working_set_t * data_set);
gboolean PromoteRsc(resource_t * rsc, node_t * next, gboolean optional,
                    pe_working_set_t * data_set);
gboolean RoleError(resource_t * rsc, node_t * next, gboolean optional, pe_working_set_t * data_set);
gboolean NullOp(resource_t * rsc, node_t * next, gboolean optional, pe_working_set_t * data_set);

/* *INDENT-OFF* */
enum rsc_role_e rsc_state_matrix[RSC_ROLE_MAX][RSC_ROLE_MAX] = {
/* Current State */
/*       Next State:    Unknown 	  Stopped	     Started	        Slave	          Master */
    /* Unknown */ { RSC_ROLE_UNKNOWN, RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, },
    /* Stopped */ { RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_STARTED, RSC_ROLE_SLAVE,   RSC_ROLE_SLAVE, },
    /* Started */ { RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_STARTED, RSC_ROLE_SLAVE,   RSC_ROLE_MASTER, },
    /* Slave */	  { RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_SLAVE,   RSC_ROLE_MASTER, },
    /* Master */  { RSC_ROLE_STOPPED, RSC_ROLE_SLAVE,   RSC_ROLE_SLAVE,   RSC_ROLE_SLAVE,   RSC_ROLE_MASTER, },
};

gboolean (*rsc_action_matrix[RSC_ROLE_MAX][RSC_ROLE_MAX])(resource_t*,node_t*,gboolean,pe_working_set_t*) = {
/* Current State */
/*       Next State:       Unknown	Stopped		Started		Slave		Master */
    /* Unknown */	{ RoleError,	StopRsc,	RoleError,	RoleError,	RoleError,  },
    /* Stopped */	{ RoleError,	NullOp,		StartRsc,	StartRsc,	RoleError,  },
    /* Started */	{ RoleError,	StopRsc,	NullOp,		NullOp,		PromoteRsc, },
    /* Slave */	        { RoleError,	StopRsc,	StopRsc, 	NullOp,		PromoteRsc, },
    /* Master */	{ RoleError,	DemoteRsc,	DemoteRsc,	DemoteRsc,	NullOp,     },
};
/* *INDENT-ON* */

struct capacity_data {
    node_t *node;
    resource_t *rsc;
    gboolean is_enough;
};

static void
check_capacity(gpointer key, gpointer value, gpointer user_data)
{
    int required = 0;
    int remaining = 0;
    struct capacity_data *data = user_data;

    required = crm_parse_int(value, "0");
    remaining = crm_parse_int(g_hash_table_lookup(data->node->details->utilization, key), "0");

    if (required > remaining) {
        pe_rsc_debug(data->rsc,
                     "Node %s has no enough %s for resource %s: required=%d remaining=%d",
                     data->node->details->uname, (char *)key, data->rsc->id, required, remaining);
        data->is_enough = FALSE;
    }
}

static gboolean
have_enough_capacity(node_t * node, resource_t * rsc)
{
    struct capacity_data data;

    data.node = node;
    data.rsc = rsc;
    data.is_enough = TRUE;

    g_hash_table_foreach(rsc->utilization, check_capacity, &data);

    return data.is_enough;
}

static gboolean
native_choose_node(resource_t * rsc, node_t * prefer, pe_working_set_t * data_set)
{
    /*
       1. Sort by weight
       2. color.chosen_node = the node (of those with the highest wieght)
       with the fewest resources
       3. remove color.chosen_node from all other colors
     */
    int alloc_details = scores_log_level + 1;

    GListPtr nodes = NULL;
    node_t *chosen = NULL;

    int lpc = 0;
    int multiple = 0;
    int length = 0;
    gboolean result = FALSE;

    if (safe_str_neq(data_set->placement_strategy, "default")) {
        GListPtr gIter = NULL;

        for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
            node_t *node = (node_t *) gIter->data;

            if (have_enough_capacity(node, rsc) == FALSE) {
                pe_rsc_debug(rsc,
                             "Resource %s cannot be allocated to node %s: none of enough capacity",
                             rsc->id, node->details->uname);
                resource_location(rsc, node, -INFINITY, "__limit_utilization_", data_set);
            }
        }
        dump_node_scores(alloc_details, rsc, "Post-utilization", rsc->allowed_nodes);
    }

    length = g_hash_table_size(rsc->allowed_nodes);

    if (is_not_set(rsc->flags, pe_rsc_provisional)) {
        return rsc->allocated_to ? TRUE : FALSE;
    }

    if (prefer) {
        chosen = g_hash_table_lookup(rsc->allowed_nodes, prefer->details->id);
        if (chosen && chosen->weight >= 0 && can_run_resources(chosen)) {
            pe_rsc_trace(rsc,
                         "Using preferred node %s for %s instead of choosing from %d candidates",
                         chosen->details->uname, rsc->id, length);
        } else if (chosen && chosen->weight < 0) {
            pe_rsc_trace(rsc, "Preferred node %s for %s was unavailable", chosen->details->uname,
                         rsc->id);
            chosen = NULL;
        } else if (chosen && can_run_resources(chosen)) {
            pe_rsc_trace(rsc, "Preferred node %s for %s was unsuitable", chosen->details->uname,
                         rsc->id);
            chosen = NULL;
        } else {
            pe_rsc_trace(rsc, "Preferred node %s for %s was unknown", prefer->details->uname,
                         rsc->id);
        }
    }

    if (chosen == NULL && rsc->allowed_nodes) {
        nodes = g_hash_table_get_values(rsc->allowed_nodes);
        nodes = g_list_sort_with_data(nodes, sort_node_weight, g_list_nth_data(rsc->running_on, 0));

        chosen = g_list_nth_data(nodes, 0);
        pe_rsc_trace(rsc, "Chose node %s for %s from %d candidates",
                     chosen ? chosen->details->uname : "<none>", rsc->id, length);

        if (chosen && chosen->weight > 0 && can_run_resources(chosen)) {
            node_t *running = g_list_nth_data(rsc->running_on, 0);

            if (running && can_run_resources(running) == FALSE) {
                pe_rsc_trace(rsc, "Current node for %s (%s) can't run resources",
                             rsc->id, running->details->uname);
                running = NULL;
            }

            for (lpc = 1; lpc < length && running; lpc++) {
                node_t *tmp = g_list_nth_data(nodes, lpc);

                if (tmp->weight == chosen->weight) {
                    multiple++;
                    if (tmp->details == running->details) {
                        /* prefer the existing node if scores are equal */
                        chosen = tmp;
                    }
                }
            }
        }
    }

    if (multiple > 1) {
        int log_level = LOG_INFO;
        char *score = score2char(chosen->weight);

        if (chosen->weight >= INFINITY) {
            log_level = LOG_WARNING;
        }

        do_crm_log(log_level, "%d nodes with equal score (%s) for"
                   " running %s resources.  Chose %s.",
                   multiple, score, rsc->id, chosen->details->uname);
        free(score);
    }

    result = native_assign_node(rsc, nodes, chosen, FALSE);
    g_list_free(nodes);
    return result;
}

static int
node_list_attr_score(GHashTable * list, const char *attr, const char *value)
{
    GHashTableIter iter;
    node_t *node = NULL;
    int best_score = -INFINITY;
    const char *best_node = NULL;

    if (attr == NULL) {
        attr = "#" XML_ATTR_UNAME;
    }

    g_hash_table_iter_init(&iter, list);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
        int weight = node->weight;

        if (can_run_resources(node) == FALSE) {
            weight = -INFINITY;
        }
        if (weight > best_score || best_node == NULL) {
            const char *tmp = g_hash_table_lookup(node->details->attrs, attr);

            if (safe_str_eq(value, tmp)) {
                best_score = weight;
                best_node = node->details->uname;
            }
        }
    }

    if (safe_str_neq(attr, "#" XML_ATTR_UNAME)) {
        crm_info("Best score for %s=%s was %s with %d",
                 attr, value, best_node ? best_node : "<none>", best_score);
    }

    return best_score;
}

static void
node_hash_update(GHashTable * list1, GHashTable * list2, const char *attr, float factor,
                 gboolean only_positive)
{
    int score = 0;
    int new_score = 0;
    GHashTableIter iter;
    node_t *node = NULL;

    if (attr == NULL) {
        attr = "#" XML_ATTR_UNAME;
    }

    g_hash_table_iter_init(&iter, list1);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
        CRM_CHECK(node != NULL, continue);
        score = node_list_attr_score(list2, attr, g_hash_table_lookup(node->details->attrs, attr));
        new_score = merge_weights(factor * score, node->weight);

        if (factor < 0 && score < 0) {
            /* Negative preference for a node with a negative score
             * should not become a positive preference
             *
             * TODO - Decide if we want to filter only if weight == -INFINITY
             *
             */
            crm_trace("%s: Filtering %d + %f*%d (factor * score)",
                      node->details->uname, node->weight, factor, score);

        } else if (node->weight == INFINITY_HACK) {
            crm_trace("%s: Filtering %d + %f*%d (node < 0)",
                      node->details->uname, node->weight, factor, score);

        } else if (only_positive && new_score < 0 && node->weight > 0) {
            node->weight = INFINITY_HACK;
            crm_trace("%s: Filtering %d + %f*%d (score > 0)",
                      node->details->uname, node->weight, factor, score);

        } else if (only_positive && new_score < 0 && node->weight == 0) {
            crm_trace("%s: Filtering %d + %f*%d (score == 0)",
                      node->details->uname, node->weight, factor, score);

        } else {
            crm_trace("%s: %d + %f*%d", node->details->uname, node->weight, factor, score);
            node->weight = new_score;
        }
    }
}

static GHashTable *
node_hash_dup(GHashTable * hash)
{
    /* Hack! */
    GListPtr list = g_hash_table_get_values(hash);
    GHashTable *result = node_hash_from_list(list);

    g_list_free(list);
    return result;
}

GHashTable *
native_merge_weights(resource_t * rsc, const char *rhs, GHashTable * nodes, const char *attr,
                     float factor, enum pe_weights flags)
{
    return rsc_merge_weights(rsc, rhs, nodes, attr, factor, flags);
}

GHashTable *
rsc_merge_weights(resource_t * rsc, const char *rhs, GHashTable * nodes, const char *attr,
                  float factor, enum pe_weights flags)
{
    GHashTable *work = NULL;
    int multiplier = 1;

    if (factor < 0) {
        multiplier = -1;
    }

    if (is_set(rsc->flags, pe_rsc_merging)) {
        pe_rsc_info(rsc, "%s: Breaking dependency loop at %s", rhs, rsc->id);
        return nodes;
    }

    set_bit(rsc->flags, pe_rsc_merging);

    if (is_set(flags, pe_weights_init)) {
        if (rsc->variant == pe_group && rsc->children) {
            GListPtr last = rsc->children;

            while (last->next != NULL) {
                last = last->next;
            }

            pe_rsc_trace(rsc, "Merging %s as a group %p %p", rsc->id, rsc->children, last);
            work = rsc_merge_weights(last->data, rhs, NULL, attr, factor, flags);

        } else {
            work = node_hash_dup(rsc->allowed_nodes);
        }
        clear_bit(flags, pe_weights_init);

    } else {
        pe_rsc_trace(rsc, "%s: Combining scores from %s", rhs, rsc->id);
        work = node_hash_dup(nodes);
        node_hash_update(work, rsc->allowed_nodes, attr, factor,
                         is_set(flags, pe_weights_positive));
    }

    if (is_set(flags, pe_weights_rollback) && can_run_any(work) == FALSE) {
        pe_rsc_info(rsc, "%s: Rolling back scores from %s", rhs, rsc->id);
        g_hash_table_destroy(work);
        clear_bit(rsc->flags, pe_rsc_merging);
        return nodes;
    }

    if (can_run_any(work)) {
        GListPtr gIter = NULL;

        if (is_set(flags, pe_weights_forward)) {
            gIter = rsc->rsc_cons;
        } else {
            gIter = rsc->rsc_cons_lhs;
        }

        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *other = NULL;
            rsc_colocation_t *constraint = (rsc_colocation_t *) gIter->data;

            if (is_set(flags, pe_weights_forward)) {
                other = constraint->rsc_rh;
            } else {
                other = constraint->rsc_lh;
            }

            pe_rsc_trace(rsc, "Applying %s (%s)", constraint->id, other->id);
            work = rsc_merge_weights(other, rhs, work, constraint->node_attribute,
                                     multiplier * (float)constraint->score / INFINITY, flags);
            dump_node_scores(LOG_TRACE, NULL, rhs, work);
        }

    }

    if (is_set(flags, pe_weights_positive)) {
        node_t *node = NULL;
        GHashTableIter iter;

        g_hash_table_iter_init(&iter, work);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
            if (node->weight == INFINITY_HACK) {
                node->weight = 1;
            }
        }
    }

    if (nodes) {
        g_hash_table_destroy(nodes);
    }

    clear_bit(rsc->flags, pe_rsc_merging);
    return work;
}

node_t *
native_color(resource_t * rsc, node_t * prefer, pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;
    int alloc_details = scores_log_level + 1;

    if (rsc->parent && is_not_set(rsc->parent->flags, pe_rsc_allocating)) {
        /* never allocate children on their own */
        pe_rsc_debug(rsc, "Escalating allocation of %s to its parent: %s", rsc->id,
                     rsc->parent->id);
        rsc->parent->cmds->allocate(rsc->parent, prefer, data_set);
    }

    if (is_not_set(rsc->flags, pe_rsc_provisional)) {
        return rsc->allocated_to;
    }

    if (is_set(rsc->flags, pe_rsc_allocating)) {
        pe_rsc_debug(rsc, "Dependency loop detected involving %s", rsc->id);
        return NULL;
    }

    set_bit(rsc->flags, pe_rsc_allocating);
    print_resource(alloc_details, "Allocating: ", rsc, FALSE);
    dump_node_scores(alloc_details, rsc, "Pre-allloc", rsc->allowed_nodes);

    for (gIter = rsc->rsc_cons; gIter != NULL; gIter = gIter->next) {
        rsc_colocation_t *constraint = (rsc_colocation_t *) gIter->data;

        GHashTable *archive = NULL;
        resource_t *rsc_rh = constraint->rsc_rh;

        pe_rsc_trace(rsc, "%s: Pre-Processing %s (%s, %d, %s)",
                     rsc->id, constraint->id, rsc_rh->id,
                     constraint->score, role2text(constraint->role_lh));
        if (constraint->role_lh >= RSC_ROLE_MASTER
            || (constraint->score < 0 && constraint->score > -INFINITY)) {
            archive = node_hash_dup(rsc->allowed_nodes);
        }
        rsc_rh->cmds->allocate(rsc_rh, NULL, data_set);
        rsc->cmds->rsc_colocation_lh(rsc, rsc_rh, constraint);
        if (archive && can_run_any(rsc->allowed_nodes) == FALSE) {
            pe_rsc_info(rsc, "%s: Rolling back scores from %s", rsc->id, rsc_rh->id);
            g_hash_table_destroy(rsc->allowed_nodes);
            rsc->allowed_nodes = archive;
            archive = NULL;
        }
        if (archive) {
            g_hash_table_destroy(archive);
        }
    }

    dump_node_scores(alloc_details, rsc, "Post-coloc", rsc->allowed_nodes);

    for (gIter = rsc->rsc_cons_lhs; gIter != NULL; gIter = gIter->next) {
        rsc_colocation_t *constraint = (rsc_colocation_t *) gIter->data;

        rsc->allowed_nodes =
            constraint->rsc_lh->cmds->merge_weights(constraint->rsc_lh, rsc->id, rsc->allowed_nodes,
                                                    constraint->node_attribute,
                                                    (float)constraint->score / INFINITY,
                                                    pe_weights_rollback);
    }

    print_resource(LOG_DEBUG_2, "Allocating: ", rsc, FALSE);
    if (rsc->next_role == RSC_ROLE_STOPPED) {
        pe_rsc_trace(rsc, "Making sure %s doesn't get allocated", rsc->id);
        /* make sure it doesnt come up again */
        resource_location(rsc, NULL, -INFINITY, XML_RSC_ATTR_TARGET_ROLE, data_set);
    }

    dump_node_scores(show_scores ? 0 : scores_log_level, rsc, __PRETTY_FUNCTION__,
                     rsc->allowed_nodes);
    if (is_set(data_set->flags, pe_flag_stonith_enabled)
        && is_set(data_set->flags, pe_flag_have_stonith_resource) == FALSE) {
        clear_bit(rsc->flags, pe_rsc_managed);
    }

    if (is_not_set(rsc->flags, pe_rsc_managed)) {
        const char *reason = NULL;
        node_t *assign_to = NULL;

        rsc->next_role = rsc->role;
        if (rsc->running_on == NULL) {
            reason = "inactive";
        } else if (rsc->role == RSC_ROLE_MASTER) {
            assign_to = rsc->running_on->data;
            reason = "master";
        } else if (is_set(rsc->flags, pe_rsc_failed)) {
            reason = "failed";
        } else {
            assign_to = rsc->running_on->data;
            reason = "active";
        }
        pe_rsc_info(rsc, "Unmanaged resource %s allocated to %s: %s", rsc->id,
                    assign_to ? assign_to->details->uname : "'nowhere'", reason);
        native_assign_node(rsc, NULL, assign_to, TRUE);

    } else if (is_set(data_set->flags, pe_flag_stop_everything)) {
        pe_rsc_debug(rsc, "Forcing %s to stop", rsc->id);
        native_assign_node(rsc, NULL, NULL, TRUE);

    } else if (is_set(rsc->flags, pe_rsc_provisional)
               && native_choose_node(rsc, prefer, data_set)) {
        pe_rsc_trace(rsc, "Allocated resource %s to %s", rsc->id,
                     rsc->allocated_to->details->uname);

    } else if (rsc->allocated_to == NULL) {
        if (is_not_set(rsc->flags, pe_rsc_orphan)) {
            pe_rsc_info(rsc, "Resource %s cannot run anywhere", rsc->id);
        } else if (rsc->running_on != NULL) {
            pe_rsc_info(rsc, "Stopping orphan resource %s", rsc->id);
        }

    } else {
        pe_rsc_debug(rsc, "Pre-Allocated resource %s to %s", rsc->id,
                     rsc->allocated_to->details->uname);
    }

    clear_bit(rsc->flags, pe_rsc_allocating);
    print_resource(LOG_DEBUG_3, "Allocated ", rsc, TRUE);

    if (rsc->is_remote_node) {
        node_t *remote_node = pe_find_node(data_set->nodes, rsc->id);

        CRM_ASSERT(remote_node != NULL);
        if (rsc->allocated_to && rsc->next_role != RSC_ROLE_STOPPED) {
            crm_trace("Setting remote node %s to ONLINE", remote_node->details->id);
            remote_node->details->online = TRUE;

        } else {
            crm_trace("Setting remote node %s to SHUTDOWN.  next role = %s, allocated=%s",
                remote_node->details->id, role2text(rsc->next_role), rsc->allocated_to ? "true" : "false");
            remote_node->details->shutdown = TRUE;
        }
    }

    return rsc->allocated_to;
}

static gboolean
is_op_dup(resource_t * rsc, const char *name, const char *interval)
{
    gboolean dup = FALSE;
    const char *id = NULL;
    const char *value = NULL;
    xmlNode *operation = NULL;

    for (operation = __xml_first_child(rsc->ops_xml); operation != NULL;
         operation = __xml_next(operation)) {
        if (crm_str_eq((const char *)operation->name, "op", TRUE)) {
            value = crm_element_value(operation, "name");
            if (safe_str_neq(value, name)) {
                continue;
            }

            value = crm_element_value(operation, XML_LRM_ATTR_INTERVAL);
            if (value == NULL) {
                value = "0";
            }

            if (safe_str_neq(value, interval)) {
                continue;
            }

            if (id == NULL) {
                id = ID(operation);

            } else {
                crm_config_err("Operation %s is a duplicate of %s", ID(operation), id);
                crm_config_err
                    ("Do not use the same (name, interval) combination more than once per resource");
                dup = TRUE;
            }
        }
    }

    return dup;
}

void
RecurringOp(resource_t * rsc, action_t * start, node_t * node,
            xmlNode * operation, pe_working_set_t * data_set)
{
    char *key = NULL;
    const char *name = NULL;
    const char *value = NULL;
    const char *interval = NULL;
    const char *node_uname = NULL;

    unsigned long long interval_ms = 0;
    action_t *mon = NULL;
    gboolean is_optional = TRUE;
    GListPtr possible_matches = NULL;

    /* Only process for the operations without role="Stopped" */
    value = crm_element_value(operation, "role");
    if (value && text2role(value) == RSC_ROLE_STOPPED) {
        return;
    }

    pe_rsc_trace(rsc, "Creating recurring action %s for %s in role %s on %s",
                 ID(operation), rsc->id, role2text(rsc->next_role),
                 node ? node->details->uname : "n/a");

    if (node != NULL) {
        node_uname = node->details->uname;
    }

    interval = crm_element_value(operation, XML_LRM_ATTR_INTERVAL);
    interval_ms = crm_get_interval(interval);

    if (interval_ms == 0) {
        return;
    }

    name = crm_element_value(operation, "name");
    if (is_op_dup(rsc, name, interval)) {
        return;
    }

    if (safe_str_eq(name, RSC_STOP)
        || safe_str_eq(name, RSC_START)
        || safe_str_eq(name, RSC_DEMOTE)
        || safe_str_eq(name, RSC_PROMOTE)
        ) {
        crm_config_err("Invalid recurring action %s wth name: '%s'", ID(operation), name);
        return;
    }

    key = generate_op_key(rsc->id, name, interval_ms);
    if (find_rsc_op_entry(rsc, key) == NULL) {
        /* disabled */
        free(key);
        return;
    }

    if (start != NULL) {
        pe_rsc_trace(rsc, "Marking %s %s due to %s",
                     key, is_set(start->flags, pe_action_optional) ? "optional" : "manditory",
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
        pe_rsc_trace(rsc, "Marking %s manditory: not active", key);
    } else {
        g_list_free(possible_matches);
    }

    if ((rsc->next_role == RSC_ROLE_MASTER && value == NULL)
        || (value != NULL && text2role(value) != rsc->next_role)) {
        int log_level = LOG_DEBUG_2;
        const char *result = "Ignoring";

        if (is_optional) {
            char *local_key = strdup(key);

            log_level = LOG_INFO;
            result = "Cancelling";
            /* its running : cancel it */

            mon = custom_action(rsc, local_key, RSC_CANCEL, node, FALSE, TRUE, data_set);

            free(mon->task);
            mon->task = strdup(RSC_CANCEL);
            add_hash_param(mon->meta, XML_LRM_ATTR_INTERVAL, interval);
            add_hash_param(mon->meta, XML_LRM_ATTR_TASK, name);

            local_key = NULL;

            switch (rsc->role) {
                case RSC_ROLE_SLAVE:
                case RSC_ROLE_STARTED:
                    if (rsc->next_role == RSC_ROLE_MASTER) {
                        local_key = promote_key(rsc);

                    } else if (rsc->next_role == RSC_ROLE_STOPPED) {
                        local_key = stop_key(rsc);
                    }

                    break;
                case RSC_ROLE_MASTER:
                    local_key = demote_key(rsc);
                    break;
                default:
                    break;
            }

            if (local_key) {
                custom_action_order(rsc, NULL, mon, rsc, local_key, NULL,
                                    pe_order_runnable_left, data_set);
            }

            mon = NULL;
        }

        do_crm_log(log_level, "%s action %s (%s vs. %s)",
                   result, key, value ? value : role2text(RSC_ROLE_SLAVE),
                   role2text(rsc->next_role));

        free(key);
        key = NULL;
        return;
    }

    mon = custom_action(rsc, key, name, node, is_optional, TRUE, data_set);
    key = mon->uuid;
    if (is_optional) {
        pe_rsc_trace(rsc, "%s\t   %s (optional)", crm_str(node_uname), mon->uuid);
    }

    if (start == NULL || is_set(start->flags, pe_action_runnable) == FALSE) {
        pe_rsc_debug(rsc, "%s\t   %s (cancelled : start un-runnable)", crm_str(node_uname),
                     mon->uuid);
        update_action_flags(mon, pe_action_runnable | pe_action_clear);

    } else if (node == NULL || node->details->online == FALSE || node->details->unclean) {
        pe_rsc_debug(rsc, "%s\t   %s (cancelled : no node available)", crm_str(node_uname),
                     mon->uuid);
        update_action_flags(mon, pe_action_runnable | pe_action_clear);

    } else if (is_set(mon->flags, pe_action_optional) == FALSE) {
        pe_rsc_info(rsc, " Start recurring %s (%llus) for %s on %s", mon->task, interval_ms / 1000,
                    rsc->id, crm_str(node_uname));
    }

    if (rsc->next_role == RSC_ROLE_MASTER) {
        char *running_master = crm_itoa(PCMK_EXECRA_RUNNING_MASTER);

        add_hash_param(mon->meta, XML_ATTR_TE_TARGET_RC, running_master);
        free(running_master);
    }

    if (node == NULL || is_set(rsc->flags, pe_rsc_managed)) {
        custom_action_order(rsc, start_key(rsc), NULL,
                            NULL, strdup(key), mon,
                            pe_order_implies_then | pe_order_runnable_left, data_set);

        if (rsc->next_role == RSC_ROLE_MASTER) {
            custom_action_order(rsc, promote_key(rsc), NULL,
                                rsc, NULL, mon,
                                pe_order_optional | pe_order_runnable_left, data_set);

        } else if (rsc->role == RSC_ROLE_MASTER) {
            custom_action_order(rsc, demote_key(rsc), NULL,
                                rsc, NULL, mon,
                                pe_order_optional | pe_order_runnable_left, data_set);
        }
    }
}

void
Recurring(resource_t * rsc, action_t * start, node_t * node, pe_working_set_t * data_set)
{
    if (is_not_set(data_set->flags, pe_flag_maintenance_mode) &&
        (node == NULL || node->details->maintenance == FALSE)) {
        xmlNode *operation = NULL;

        for (operation = __xml_first_child(rsc->ops_xml); operation != NULL;
             operation = __xml_next(operation)) {
            if (crm_str_eq((const char *)operation->name, "op", TRUE)) {
                RecurringOp(rsc, start, node, operation, data_set);
            }
        }
    }
}

void
RecurringOp_Stopped(resource_t * rsc, action_t * start, node_t * node,
                    xmlNode * operation, pe_working_set_t * data_set)
{
    char *key = NULL;
    const char *name = NULL;
    const char *role = NULL;
    const char *interval = NULL;
    const char *node_uname = NULL;

    unsigned long long interval_ms = 0;
    GListPtr possible_matches = NULL;
    GListPtr gIter = NULL;

    /* TODO: Support of non-unique clone */
    if (is_set(rsc->flags, pe_rsc_unique) == FALSE) {
        return;
    }

    /* Only process for the operations with role="Stopped" */
    role = crm_element_value(operation, "role");
    if (role == NULL || text2role(role) != RSC_ROLE_STOPPED) {
        return;
    }

    pe_rsc_trace(rsc,
                 "Creating recurring actions %s for %s in role %s on nodes where it'll not be running",
                 ID(operation), rsc->id, role2text(rsc->next_role));

    if (node != NULL) {
        node_uname = node->details->uname;
    }

    interval = crm_element_value(operation, XML_LRM_ATTR_INTERVAL);
    interval_ms = crm_get_interval(interval);

    if (interval_ms == 0) {
        return;
    }

    name = crm_element_value(operation, "name");
    if (is_op_dup(rsc, name, interval)) {
        return;
    }

    if (safe_str_eq(name, RSC_STOP)
        || safe_str_eq(name, RSC_START)
        || safe_str_eq(name, RSC_DEMOTE)
        || safe_str_eq(name, RSC_PROMOTE)
        ) {
        crm_config_err("Invalid recurring action %s wth name: '%s'", ID(operation), name);
        return;
    }

    key = generate_op_key(rsc->id, name, interval_ms);
    if (find_rsc_op_entry(rsc, key) == NULL) {
        /* disabled */
        free(key);
        return;
    }

    /* if the monitor exists on the node where the resource will be running, cancel it */
    if (node != NULL) {
        possible_matches = find_actions_exact(rsc->actions, key, node);
        if (possible_matches) {
            action_t *cancel_op = NULL;
            char *local_key = strdup(key);

            g_list_free(possible_matches);

            cancel_op = custom_action(rsc, local_key, RSC_CANCEL, node, FALSE, TRUE, data_set);

            free(cancel_op->task);
            cancel_op->task = strdup(RSC_CANCEL);
            add_hash_param(cancel_op->meta, XML_LRM_ATTR_INTERVAL, interval);
            add_hash_param(cancel_op->meta, XML_LRM_ATTR_TASK, name);

            local_key = NULL;

            if (rsc->next_role == RSC_ROLE_STARTED || rsc->next_role == RSC_ROLE_SLAVE) {
                /* rsc->role == RSC_ROLE_STOPPED: cancel the monitor before start */
                /* rsc->role == RSC_ROLE_STARTED: for a migration, cancel the monitor on the target node before start */
                custom_action_order(rsc, NULL, cancel_op, rsc, start_key(rsc), NULL,
                                    pe_order_runnable_left, data_set);
            }

            pe_rsc_info(rsc, "Cancel action %s (%s vs. %s) on %s",
                        key, role, role2text(rsc->next_role), crm_str(node_uname));
        }
    }

    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        node_t *stop_node = (node_t *) gIter->data;
        const char *stop_node_uname = stop_node->details->uname;
        gboolean is_optional = TRUE;
        gboolean probe_is_optional = TRUE;
        gboolean stop_is_optional = TRUE;
        action_t *stopped_mon = NULL;
        char *rc_inactive = NULL;
        GListPtr probe_complete_ops = NULL;
        GListPtr stop_ops = NULL;
        GListPtr local_gIter = NULL;
        char *stop_op_key = NULL;

        if (node_uname && safe_str_eq(stop_node_uname, node_uname)) {
            continue;
        }

        pe_rsc_trace(rsc, "Creating recurring action %s for %s on %s",
                     ID(operation), rsc->id, crm_str(stop_node_uname));

        /* start a monitor for an already stopped resource */
        possible_matches = find_actions_exact(rsc->actions, key, stop_node);
        if (possible_matches == NULL) {
            pe_rsc_trace(rsc, "Marking %s manditory on %s: not active", key,
                         crm_str(stop_node_uname));
            is_optional = FALSE;
        } else {
            pe_rsc_trace(rsc, "Marking %s optional on %s: already active", key,
                         crm_str(stop_node_uname));
            is_optional = TRUE;
            g_list_free(possible_matches);
        }

        stopped_mon = custom_action(rsc, strdup(key), name, stop_node, is_optional, TRUE, data_set);

        rc_inactive = crm_itoa(PCMK_EXECRA_NOT_RUNNING);
        add_hash_param(stopped_mon->meta, XML_ATTR_TE_TARGET_RC, rc_inactive);
        free(rc_inactive);

        probe_complete_ops = find_actions(data_set->actions, CRM_OP_PROBED, NULL);
        for (local_gIter = probe_complete_ops; local_gIter != NULL; local_gIter = local_gIter->next) {
            action_t *probe_complete = (action_t *) local_gIter->data;

            if (probe_complete->node == NULL) {
                if (is_set(probe_complete->flags, pe_action_optional) == FALSE) {
                    probe_is_optional = FALSE;
                }

                if (is_set(probe_complete->flags, pe_action_runnable) == FALSE) {
                    crm_debug("%s\t   %s (cancelled : probe un-runnable)",
                              crm_str(stop_node_uname), stopped_mon->uuid);
                    update_action_flags(stopped_mon, pe_action_runnable | pe_action_clear);
                }

                if (is_set(rsc->flags, pe_rsc_managed)) {
                    custom_action_order(NULL, NULL, probe_complete,
                                        NULL, strdup(key), stopped_mon,
                                        pe_order_optional, data_set);
                }
                break;
            }
        }

        if (probe_complete_ops) {
            g_list_free(probe_complete_ops);
        }

        stop_op_key = stop_key(rsc);
        stop_ops = find_actions_exact(rsc->actions, stop_op_key, stop_node);

        for (local_gIter = stop_ops; local_gIter != NULL; local_gIter = local_gIter->next) {
            action_t *stop = (action_t *) local_gIter->data;

            if (is_set(stop->flags, pe_action_optional) == FALSE) {
                stop_is_optional = FALSE;
            }

            if (is_set(stop->flags, pe_action_runnable) == FALSE) {
                crm_debug("%s\t   %s (cancelled : stop un-runnable)",
                          crm_str(stop_node_uname), stopped_mon->uuid);
                update_action_flags(stopped_mon, pe_action_runnable | pe_action_clear);
            }

            if (is_set(rsc->flags, pe_rsc_managed)) {
                custom_action_order(rsc, strdup(stop_op_key), stop,
                                    NULL, strdup(key), stopped_mon,
                                    pe_order_implies_then | pe_order_runnable_left, data_set);
            }

        }

        if (stop_ops) {
            g_list_free(stop_ops);
        }
        free(stop_op_key);

        if (is_optional == FALSE && probe_is_optional && stop_is_optional
            && is_set(rsc->flags, pe_rsc_managed) == FALSE) {
            pe_rsc_trace(rsc, "Marking %s optional on %s due to unmanaged",
                         key, crm_str(stop_node_uname));
            update_action_flags(stopped_mon, pe_action_optional);
        }

        if (is_set(stopped_mon->flags, pe_action_optional)) {
            pe_rsc_trace(rsc, "%s\t   %s (optional)", crm_str(stop_node_uname), stopped_mon->uuid);
        }

        if (stop_node->details->online == FALSE || stop_node->details->unclean) {
            pe_rsc_debug(rsc, "%s\t   %s (cancelled : no node available)",
                         crm_str(stop_node_uname), stopped_mon->uuid);
            update_action_flags(stopped_mon, pe_action_runnable | pe_action_clear);
        }

        if (is_set(stopped_mon->flags, pe_action_runnable)
            && is_set(stopped_mon->flags, pe_action_optional) == FALSE) {
            crm_notice(" Start recurring %s (%llus) for %s on %s", stopped_mon->task,
                       interval_ms / 1000, rsc->id, crm_str(stop_node_uname));
        }
    }

    free(key);
}

void
Recurring_Stopped(resource_t * rsc, action_t * start, node_t * node, pe_working_set_t * data_set)
{
    if (is_not_set(data_set->flags, pe_flag_maintenance_mode) && 
        (node == NULL || node->details->maintenance == FALSE)) {
        xmlNode *operation = NULL;

        for (operation = __xml_first_child(rsc->ops_xml); operation != NULL;
             operation = __xml_next(operation)) {
            if (crm_str_eq((const char *)operation->name, "op", TRUE)) {
                RecurringOp_Stopped(rsc, start, node, operation, data_set);
            }
        }
    }
}

void
native_create_actions(resource_t * rsc, pe_working_set_t * data_set)
{
    action_t *start = NULL;
    node_t *chosen = NULL;
    node_t *current = NULL;
    gboolean need_stop = FALSE;

    GListPtr gIter = NULL;
    int num_active_nodes = 0;
    enum rsc_role_e role = RSC_ROLE_UNKNOWN;
    enum rsc_role_e next_role = RSC_ROLE_UNKNOWN;

    chosen = rsc->allocated_to;
    if (chosen != NULL && rsc->next_role == RSC_ROLE_UNKNOWN) {
        rsc->next_role = RSC_ROLE_STARTED;
        pe_rsc_trace(rsc, "Fixed next_role: unknown -> %s", role2text(rsc->next_role));

    } else if (rsc->next_role == RSC_ROLE_UNKNOWN) {
        rsc->next_role = RSC_ROLE_STOPPED;
        pe_rsc_trace(rsc, "Fixed next_role: unknown -> %s", role2text(rsc->next_role));
    }

    pe_rsc_trace(rsc, "Processing state transition for %s %p: %s->%s", rsc->id, rsc,
                 role2text(rsc->role), role2text(rsc->next_role));

    if (rsc->running_on) {
        current = rsc->running_on->data;
    }

    for (gIter = rsc->running_on; gIter != NULL; gIter = gIter->next) {
        /* node_t *n = (node_t *) gIter->data; */

        num_active_nodes++;
    }

    get_rsc_attributes(rsc->parameters, rsc, chosen, data_set);

    for (gIter = rsc->dangling_migrations; gIter != NULL; gIter = gIter->next) {
        node_t *current = (node_t *) gIter->data;

        action_t *stop = stop_action(rsc, current, FALSE);

        set_bit(stop->flags, pe_action_dangle);
        pe_rsc_trace(rsc, "Forcing a cleanup of %s on %s", rsc->id, current->details->uname);

        if (is_set(data_set->flags, pe_flag_remove_after_stop)) {
            DeleteRsc(rsc, current, FALSE, data_set);
        }
    }

    if (num_active_nodes > 1) {

        if (num_active_nodes == 2
            && chosen
            && rsc->partial_migration_target
            && (chosen->details == rsc->partial_migration_target->details)) {
            /* Here the chosen node is still the migration target from a partial
             * migration. Attempt to continue the migration instead of recovering
             * by stopping the resource everywhere and starting it on a single node. */
            pe_rsc_trace(rsc,
                         "Will attempt to continue with a partial migration to target %s from %s",
                         rsc->partial_migration_target->details->id,
                         rsc->partial_migration_source->details->id);
        } else {
            const char *type = crm_element_value(rsc->xml, XML_ATTR_TYPE);
            const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);

            pe_proc_err("Resource %s (%s::%s) is active on %d nodes %s",
                        rsc->id, class, type, num_active_nodes, recovery2text(rsc->recovery_type));
            crm_warn("See %s for more information.",
                     "http://clusterlabs.org/wiki/FAQ#Resource_is_Too_Active");

            if (rsc->recovery_type == recovery_stop_start) {
                need_stop = TRUE;
            }

            /* If by chance a partial migration is in process,
             * but the migration target is not chosen still, clear all
             * partial migration data.  */
            rsc->partial_migration_source = rsc->partial_migration_target = NULL;
        }
    }

    if (is_set(rsc->flags, pe_rsc_start_pending)) {
        start = start_action(rsc, chosen, TRUE);
        set_bit(start->flags, pe_action_print_always);
    }

    if (current && chosen && current->details != chosen->details) {
        pe_rsc_trace(rsc, "Moving %s", rsc->id);
        need_stop = TRUE;

    } else if (is_set(rsc->flags, pe_rsc_failed)) {
        pe_rsc_trace(rsc, "Recovering %s", rsc->id);
        need_stop = TRUE;

    } else if (is_set(rsc->flags, pe_rsc_block)) {
        pe_rsc_trace(rsc, "Block %s", rsc->id);
        need_stop = TRUE;

    } else if (rsc->role > RSC_ROLE_STARTED && current != NULL && chosen != NULL) {
        /* Recovery of a promoted resource */
        start = start_action(rsc, chosen, TRUE);
        if (is_set(start->flags, pe_action_optional) == FALSE) {
            pe_rsc_trace(rsc, "Forced start %s", rsc->id);
            need_stop = TRUE;
        }
    }

    pe_rsc_trace(rsc, "Creating actions for %s: %s->%s", rsc->id,
                 role2text(rsc->role), role2text(rsc->next_role));

    role = rsc->role;
    /* Potentiall optional steps on brining the resource down and back up to the same level */
    while (role != RSC_ROLE_STOPPED) {
        next_role = rsc_state_matrix[role][RSC_ROLE_STOPPED];
        pe_rsc_trace(rsc, "Down: Executing: %s->%s (%s)%s", role2text(role), role2text(next_role),
                     rsc->id, need_stop ? " required" : "");
        if (rsc_action_matrix[role][next_role] (rsc, current, !need_stop, data_set) == FALSE) {
            break;
        }
        role = next_role;
    }


    while (rsc->role <= rsc->next_role && role != rsc->role && is_not_set(rsc->flags, pe_rsc_block)) {
        next_role = rsc_state_matrix[role][rsc->role];
        pe_rsc_trace(rsc, "Up:   Executing: %s->%s (%s)%s", role2text(role), role2text(next_role),
                     rsc->id, need_stop ? " required" : "");
        if (rsc_action_matrix[role][next_role] (rsc, chosen, !need_stop, data_set) == FALSE) {
            break;
        }
        role = next_role;
    }
    role = rsc->role;

    /* Required steps from this role to the next */
    while (role != rsc->next_role) {
        next_role = rsc_state_matrix[role][rsc->next_role];
        pe_rsc_trace(rsc, "Role: Executing: %s->%s = (%s)", role2text(role),
                     role2text(rsc->next_role), role2text(next_role), rsc->id);
        if (rsc_action_matrix[role][next_role] (rsc, chosen, FALSE, data_set) == FALSE) {
            break;
        }
        role = next_role;
    }

    if(is_set(rsc->flags, pe_rsc_block)) {
        pe_rsc_trace(rsc, "No monitor additional ops for blocked resource");

    } else if (rsc->next_role != RSC_ROLE_STOPPED || is_set(rsc->flags, pe_rsc_managed) == FALSE) {
        pe_rsc_trace(rsc, "Monitor ops for active resource");
        start = start_action(rsc, chosen, TRUE);
        Recurring(rsc, start, chosen, data_set);
        Recurring_Stopped(rsc, start, chosen, data_set);
    } else {
        pe_rsc_trace(rsc, "Monitor ops for in-active resource");
        Recurring_Stopped(rsc, NULL, NULL, data_set);
    }
}

static void
rsc_avoids_remote_nodes(resource_t *rsc)
{
    GHashTableIter iter;
    node_t *node = NULL;
    g_hash_table_iter_init(&iter, rsc->allowed_nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
        if (node->details->remote_rsc) {
            node->weight = -INFINITY;
        }
    }
}

void
native_internal_constraints(resource_t * rsc, pe_working_set_t * data_set)
{
    /* This function is on the critical path and worth optimizing as much as possible */

    resource_t *top = uber_parent(rsc);
    int type = pe_order_optional | pe_order_implies_then | pe_order_restart;
    gboolean is_stonith =
        (rsc->xml && safe_str_eq(crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS), "stonith")) ?
        TRUE : FALSE;

    custom_action_order(rsc, generate_op_key(rsc->id, RSC_STOP, 0), NULL,
                        rsc, generate_op_key(rsc->id, RSC_START, 0), NULL, type, data_set);

    if (top->variant == pe_master || rsc->role > RSC_ROLE_SLAVE) {
        custom_action_order(rsc, generate_op_key(rsc->id, RSC_DEMOTE, 0), NULL,
                            rsc, generate_op_key(rsc->id, RSC_STOP, 0), NULL,
                            pe_order_implies_first_master, data_set);

        custom_action_order(rsc, generate_op_key(rsc->id, RSC_START, 0), NULL,
                            rsc, generate_op_key(rsc->id, RSC_PROMOTE, 0), NULL,
                            pe_order_runnable_left, data_set);
    }

    if (is_not_set(rsc->flags, pe_rsc_managed)) {
        pe_rsc_trace(rsc, "Skipping fencing constraints for unmanaged resource: %s", rsc->id);
        return;
    }

    {
        action_t *all_stopped = get_pseudo_op(ALL_STOPPED, data_set);

        custom_action_order(rsc, stop_key(rsc), NULL,
                            NULL, strdup(all_stopped->task), all_stopped,
                            pe_order_implies_then | pe_order_runnable_left, data_set);
    }

    if (g_hash_table_size(rsc->utilization) > 0
        && safe_str_neq(data_set->placement_strategy, "default")) {
        GHashTableIter iter;
        node_t *next = NULL;
        GListPtr gIter = NULL;

        pe_rsc_trace(rsc, "Creating utilization constraints for %s - strategy: %s",
                     rsc->id, data_set->placement_strategy);

        for (gIter = rsc->running_on; gIter != NULL; gIter = gIter->next) {
            node_t *current = (node_t *) gIter->data;

            char *load_stopped_task = crm_concat(LOAD_STOPPED, current->details->uname, '_');
            action_t *load_stopped = get_pseudo_op(load_stopped_task, data_set);

            if (load_stopped->node == NULL) {
                load_stopped->node = node_copy(current);
                update_action_flags(load_stopped, pe_action_optional | pe_action_clear);
            }

            custom_action_order(rsc, stop_key(rsc), NULL,
                                NULL, load_stopped_task, load_stopped, pe_order_load, data_set);
        }

        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&next)) {
            char *load_stopped_task = crm_concat(LOAD_STOPPED, next->details->uname, '_');
            action_t *load_stopped = get_pseudo_op(load_stopped_task, data_set);

            if (load_stopped->node == NULL) {
                load_stopped->node = node_copy(next);
                update_action_flags(load_stopped, pe_action_optional | pe_action_clear);
            }

            custom_action_order(NULL, strdup(load_stopped_task), load_stopped,
                                rsc, start_key(rsc), NULL, pe_order_load, data_set);

            free(load_stopped_task);
        }
    }

    if (rsc->container) {
        crm_trace("Generating order and colocation rules for rsc %s with container %s", rsc->id, rsc->container->id);
        custom_action_order(rsc->container, generate_op_key(rsc->container->id, RSC_START, 0), NULL,
                            rsc, generate_op_key(rsc->id, RSC_START, 0), NULL,
                            pe_order_implies_then | pe_order_runnable_left, data_set);

        custom_action_order(rsc, generate_op_key(rsc->id, RSC_STOP, 0), NULL,
                            rsc->container, generate_op_key(rsc->container->id, RSC_STOP, 0), NULL,
                            pe_order_implies_first, data_set);

        rsc_colocation_new("resource-with-containter", NULL, INFINITY, rsc, rsc->container, NULL,
                           NULL, data_set);
    }

    if (rsc->is_remote_node || is_stonith) {
        /* don't allow remote nodes to run stonith devices
         * or remote connection resources.*/
        rsc_avoids_remote_nodes(rsc);
    }

    /* If this rsc is a remote connection resource associated
     * with a container ( which will most likely be a virtual guest )
     * do not allow the container to live on any remote-nodes.
     * remote-nodes managing nested remote-nodes should not be allowed. */
    if (rsc->is_remote_node && rsc->container) {
        rsc_avoids_remote_nodes(rsc->container);
    }
}

void
native_rsc_colocation_lh(resource_t * rsc_lh, resource_t * rsc_rh, rsc_colocation_t * constraint)
{
    if (rsc_lh == NULL) {
        pe_err("rsc_lh was NULL for %s", constraint->id);
        return;

    } else if (constraint->rsc_rh == NULL) {
        pe_err("rsc_rh was NULL for %s", constraint->id);
        return;
    }

    pe_rsc_trace(rsc_lh, "Processing colocation constraint between %s and %s", rsc_lh->id,
                 rsc_rh->id);

    rsc_rh->cmds->rsc_colocation_rh(rsc_lh, rsc_rh, constraint);
}

enum filter_colocation_res {
    influence_nothing = 0,
    influence_rsc_location,
    influence_rsc_priority,
};

static enum filter_colocation_res
filter_colocation_constraint(resource_t * rsc_lh, resource_t * rsc_rh,
                             rsc_colocation_t * constraint)
{
    if (constraint->score == 0) {
        return influence_nothing;
    }

    /* rh side must be allocated before we can process constraint */
    if (is_set(rsc_rh->flags, pe_rsc_provisional)) {
        return influence_nothing;
    }

    if ((constraint->role_lh >= RSC_ROLE_SLAVE) &&
        rsc_lh->parent &&
        rsc_lh->parent->variant == pe_master && is_not_set(rsc_lh->flags, pe_rsc_provisional)) {

        /* LH and RH resources have already been allocated, place the correct
         * priority oh LH rsc for the given multistate resource role */
        return influence_rsc_priority;
    }

    if (is_not_set(rsc_lh->flags, pe_rsc_provisional)) {
        /* error check */
        struct node_shared_s *details_lh;
        struct node_shared_s *details_rh;

        if ((constraint->score > -INFINITY) && (constraint->score < INFINITY)) {
            return influence_nothing;
        }

        details_rh = rsc_rh->allocated_to ? rsc_rh->allocated_to->details : NULL;
        details_lh = rsc_lh->allocated_to ? rsc_lh->allocated_to->details : NULL;

        if (constraint->score == INFINITY && details_lh != details_rh) {
            crm_err("%s and %s are both allocated"
                    " but to different nodes: %s vs. %s",
                    rsc_lh->id, rsc_rh->id,
                    details_lh ? details_lh->uname : "n/a", details_rh ? details_rh->uname : "n/a");

        } else if (constraint->score == -INFINITY && details_lh == details_rh) {
            crm_err("%s and %s are both allocated"
                    " but to the SAME node: %s",
                    rsc_lh->id, rsc_rh->id, details_rh ? details_rh->uname : "n/a");
        }

        return influence_nothing;
    }

    if (constraint->score > 0
        && constraint->role_lh != RSC_ROLE_UNKNOWN && constraint->role_lh != rsc_lh->next_role) {
        crm_trace("LH: Skipping constraint: \"%s\" state filter nextrole is %s",
                  role2text(constraint->role_lh), role2text(rsc_lh->next_role));
        return influence_nothing;
    }

    if (constraint->score > 0
        && constraint->role_rh != RSC_ROLE_UNKNOWN && constraint->role_rh != rsc_rh->next_role) {
        crm_trace("RH: Skipping constraint: \"%s\" state filter", role2text(constraint->role_rh));
        return FALSE;
    }

    if (constraint->score < 0
        && constraint->role_lh != RSC_ROLE_UNKNOWN && constraint->role_lh == rsc_lh->next_role) {
        crm_trace("LH: Skipping -ve constraint: \"%s\" state filter",
                  role2text(constraint->role_lh));
        return influence_nothing;
    }

    if (constraint->score < 0
        && constraint->role_rh != RSC_ROLE_UNKNOWN && constraint->role_rh == rsc_rh->next_role) {
        crm_trace("RH: Skipping -ve constraint: \"%s\" state filter",
                  role2text(constraint->role_rh));
        return influence_nothing;
    }

    return influence_rsc_location;
}

static void
influence_priority(resource_t * rsc_lh, resource_t * rsc_rh, rsc_colocation_t * constraint)
{
    const char *rh_value = NULL;
    const char *lh_value = NULL;
    const char *attribute = "#id";
    int score_multiplier = 1;

    if (constraint->node_attribute != NULL) {
        attribute = constraint->node_attribute;
    }

    if (!rsc_rh->allocated_to || !rsc_lh->allocated_to) {
        return;
    }

    lh_value = g_hash_table_lookup(rsc_lh->allocated_to->details->attrs, attribute);
    rh_value = g_hash_table_lookup(rsc_rh->allocated_to->details->attrs, attribute);

    if (!safe_str_eq(lh_value, rh_value)) {
        return;
    }

    if (constraint->role_rh && (constraint->role_rh != rsc_rh->next_role)) {
        return;
    }

    if (constraint->role_lh == RSC_ROLE_SLAVE) {
        score_multiplier = -1;
    }

    rsc_lh->priority = merge_weights(score_multiplier * constraint->score, rsc_lh->priority);
}

static void
colocation_match(resource_t * rsc_lh, resource_t * rsc_rh, rsc_colocation_t * constraint)
{
    const char *tmp = NULL;
    const char *value = NULL;
    const char *attribute = "#id";

    GHashTable *work = NULL;
    gboolean do_check = FALSE;

    GHashTableIter iter;
    node_t *node = NULL;

    if (constraint->node_attribute != NULL) {
        attribute = constraint->node_attribute;
    }

    if (rsc_rh->allocated_to) {
        value = g_hash_table_lookup(rsc_rh->allocated_to->details->attrs, attribute);
        do_check = TRUE;

    } else if (constraint->score < 0) {
        /* nothing to do:
         *   anti-colocation with something thats not running
         */
        return;
    }

    work = node_hash_dup(rsc_lh->allowed_nodes);

    g_hash_table_iter_init(&iter, work);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
        tmp = g_hash_table_lookup(node->details->attrs, attribute);
        if (do_check && safe_str_eq(tmp, value)) {
            if (constraint->score < INFINITY) {
                pe_rsc_trace(rsc_lh, "%s: %s.%s += %d", constraint->id, rsc_lh->id,
                             node->details->uname, constraint->score);
                node->weight = merge_weights(constraint->score, node->weight);
            }

        } else if (do_check == FALSE || constraint->score >= INFINITY) {
            pe_rsc_trace(rsc_lh, "%s: %s.%s -= %d (%s)", constraint->id, rsc_lh->id,
                         node->details->uname, constraint->score,
                         do_check ? "failed" : "unallocated");
            node->weight = merge_weights(-constraint->score, node->weight);
        }
    }

    if (can_run_any(work)
        || constraint->score <= -INFINITY || constraint->score >= INFINITY) {
        g_hash_table_destroy(rsc_lh->allowed_nodes);
        rsc_lh->allowed_nodes = work;
        work = NULL;

    } else {
        char *score = score2char(constraint->score);

        pe_rsc_info(rsc_lh, "%s: Rolling back scores from %s (%d, %s)",
                    rsc_lh->id, rsc_rh->id, do_check, score);
        free(score);
    }

    if (work) {
        g_hash_table_destroy(work);
    }
}

void
native_rsc_colocation_rh(resource_t * rsc_lh, resource_t * rsc_rh, rsc_colocation_t * constraint)
{
    enum filter_colocation_res filter_results;

    filter_results = filter_colocation_constraint(rsc_lh, rsc_rh, constraint);

    switch (filter_results) {
        case influence_rsc_priority:
            influence_priority(rsc_lh, rsc_rh, constraint);
            break;
        case influence_rsc_location:
            pe_rsc_trace(rsc_lh, "%sColocating %s with %s (%s, weight=%d)",
                         constraint->score >= 0 ? "" : "Anti-",
                         rsc_lh->id, rsc_rh->id, constraint->id, constraint->score);
            colocation_match(rsc_lh, rsc_rh, constraint);
            break;
        case influence_nothing:
        default:
            return;
    }
}

static gboolean
filter_rsc_ticket(resource_t * rsc_lh, rsc_ticket_t * rsc_ticket)
{
    if (rsc_ticket->role_lh != RSC_ROLE_UNKNOWN && rsc_ticket->role_lh != rsc_lh->role) {
        pe_rsc_trace(rsc_lh, "LH: Skipping constraint: \"%s\" state filter",
                     role2text(rsc_ticket->role_lh));
        return FALSE;
    }

    return TRUE;
}

void
rsc_ticket_constraint(resource_t * rsc_lh, rsc_ticket_t * rsc_ticket, pe_working_set_t * data_set)
{
    if (rsc_ticket == NULL) {
        pe_err("rsc_ticket was NULL");
        return;
    }

    if (rsc_lh == NULL) {
        pe_err("rsc_lh was NULL for %s", rsc_ticket->id);
        return;
    }

    if (rsc_ticket->ticket->granted && rsc_ticket->ticket->standby == FALSE) {
        return;
    }

    if (rsc_lh->children) {
        GListPtr gIter = rsc_lh->children;

        pe_rsc_trace(rsc_lh, "Processing ticket dependencies from %s", rsc_lh->id);

        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child_rsc = (resource_t *) gIter->data;

            rsc_ticket_constraint(child_rsc, rsc_ticket, data_set);
        }
        return;
    }

    pe_rsc_trace(rsc_lh, "%s: Processing ticket dependency on %s (%s, %s)",
                 rsc_lh->id, rsc_ticket->ticket->id, rsc_ticket->id,
                 role2text(rsc_ticket->role_lh));

    if (rsc_ticket->ticket->granted == FALSE && g_list_length(rsc_lh->running_on) > 0) {
        GListPtr gIter = NULL;

        switch (rsc_ticket->loss_policy) {
            case loss_ticket_stop:
                resource_location(rsc_lh, NULL, -INFINITY, "__loss_of_ticket__", data_set);
                break;

            case loss_ticket_demote:
                /*Promotion score will be set to -INFINITY in master_promotion_order() */
                if (rsc_ticket->role_lh != RSC_ROLE_MASTER) {
                    resource_location(rsc_lh, NULL, -INFINITY, "__loss_of_ticket__", data_set);
                }
                break;

            case loss_ticket_fence:
                if (filter_rsc_ticket(rsc_lh, rsc_ticket) == FALSE) {
                    return;
                }

                resource_location(rsc_lh, NULL, -INFINITY, "__loss_of_ticket__", data_set);

                for (gIter = rsc_lh->running_on; gIter != NULL; gIter = gIter->next) {
                    node_t *node = (node_t *) gIter->data;

                    crm_warn("Node %s will be fenced for deadman", node->details->uname);
                    node->details->unclean = TRUE;
                }
                break;

            case loss_ticket_freeze:
                if (filter_rsc_ticket(rsc_lh, rsc_ticket) == FALSE) {
                    return;
                }
                if (g_list_length(rsc_lh->running_on) > 0) {
                    clear_bit(rsc_lh->flags, pe_rsc_managed);
                    set_bit(rsc_lh->flags, pe_rsc_block);
                }
                break;
        }

    } else if (rsc_ticket->ticket->granted == FALSE) {

        if (rsc_ticket->role_lh != RSC_ROLE_MASTER || rsc_ticket->loss_policy == loss_ticket_stop) {
            resource_location(rsc_lh, NULL, -INFINITY, "__no_ticket__", data_set);
        }

    } else if (rsc_ticket->ticket->standby) {

        if (rsc_ticket->role_lh != RSC_ROLE_MASTER || rsc_ticket->loss_policy == loss_ticket_stop) {
            resource_location(rsc_lh, NULL, -INFINITY, "__ticket_standby__", data_set);
        }
    }
}

enum pe_action_flags
native_action_flags(action_t * action, node_t * node)
{
    return action->flags;
}

enum pe_graph_flags
native_update_actions(action_t * first, action_t * then, node_t * node, enum pe_action_flags flags,
                      enum pe_action_flags filter, enum pe_ordering type)
{
    /* flags == get_action_flags(first, then_node) called from update_action() */
    enum pe_graph_flags changed = pe_graph_none;
    enum pe_action_flags then_flags = then->flags;
    enum pe_action_flags first_flags = first->flags;

    if (type & pe_order_asymmetrical) {
        resource_t *then_rsc = then->rsc;
        enum rsc_role_e then_rsc_role = then_rsc ? then_rsc->fns->state(then_rsc, TRUE) : 0;

        if (!then_rsc) {
            /* ignore */
        } else if ((then_rsc_role == RSC_ROLE_STOPPED) && safe_str_eq(then->task, RSC_STOP)) {
            /* ignore... if 'then' is supposed to be stopped after 'first', but
             * then is already stopped, there is nothing to be done when non-symmetrical.  */
        } else if ((then_rsc_role == RSC_ROLE_STARTED) && safe_str_eq(then->task, RSC_START)) {
            /* ignore... if 'then' is supposed to be started after 'first', but
             * then is already started, there is nothing to be done when non-symmetrical.  */
        } else if (!(first->flags & pe_action_runnable)) {
            /* prevent 'then' action from happening if 'first' is not runnable and
             * 'then' has not yet occurred. */
            pe_clear_action_bit(then, pe_action_runnable);
            pe_clear_action_bit(then, pe_action_optional);
            pe_rsc_trace(then->rsc, "Unset optional and runnable on %s", then->uuid);
        } else {
            /* ignore... then is allowed to start/stop if it wants to. */
        }
    }

    if (type & pe_order_implies_first) {
        if ((filter & pe_action_optional) && (flags & pe_action_optional) == 0) {
            pe_rsc_trace(first->rsc, "Unset optional on %s because of %s", first->uuid, then->uuid);
            pe_clear_action_bit(first, pe_action_optional);
        }
    }

    if (type & pe_order_implies_first_master) {
        if ((filter & pe_action_optional) &&
            ((then->flags & pe_action_optional) == FALSE) &&
            then->rsc && (then->rsc->role == RSC_ROLE_MASTER)) {
            clear_bit(first->flags, pe_action_optional);
        }
    }

    if (is_set(type, pe_order_runnable_left)
        && is_set(filter, pe_action_runnable)
        && is_set(then->flags, pe_action_runnable)
        && is_set(flags, pe_action_runnable) == FALSE) {
        pe_rsc_trace(then->rsc, "Unset runnable on %s because of %s", then->uuid, first->uuid);
        pe_clear_action_bit(then, pe_action_runnable);
    }

    if (is_set(type, pe_order_implies_then)
        && is_set(filter, pe_action_optional)
        && is_set(then->flags, pe_action_optional)
        && is_set(flags, pe_action_optional) == FALSE) {
        pe_rsc_trace(then->rsc, "Unset optional on %s because of %s", then->uuid, first->uuid);
        pe_clear_action_bit(then, pe_action_optional);
    }

    if (is_set(type, pe_order_restart)) {
        const char *reason = NULL;

        CRM_ASSERT(first->rsc && first->rsc->variant == pe_native);
        CRM_ASSERT(then->rsc && then->rsc->variant == pe_native);

        if ((filter & pe_action_runnable) && (then->flags & pe_action_runnable) == 0) {
            reason = "shutdown";
        }

        if ((filter & pe_action_optional) && (then->flags & pe_action_optional) == 0) {
            reason = "recover";
        }

        if (reason && is_set(first->flags, pe_action_optional)
            && is_set(first->flags, pe_action_runnable)) {
            pe_rsc_trace(first->rsc, "Handling %s: %s -> %s", reason, first->uuid, then->uuid);
            pe_clear_action_bit(first, pe_action_optional);
        }

        if (reason && is_not_set(first->flags, pe_action_optional)
            && is_not_set(first->flags, pe_action_runnable)) {
            pe_rsc_trace(then->rsc, "Handling %s: %s -> %s", reason, first->uuid, then->uuid);
            pe_clear_action_bit(then, pe_action_runnable);
        }
    }

    if (then_flags != then->flags) {
        changed |= pe_graph_updated_then;
        pe_rsc_trace(then->rsc,
                     "Then: Flags for %s on %s are now  0x%.6x (was 0x%.6x) because of %s 0x%.6x",
                     then->uuid, then->node ? then->node->details->uname : "[none]", then->flags,
                     then_flags, first->uuid, first->flags);
    }

    if (first_flags != first->flags) {
        changed |= pe_graph_updated_first;
        pe_rsc_trace(first->rsc,
                     "First: Flags for %s on %s are now  0x%.6x (was 0x%.6x) because of %s 0x%.6x",
                     first->uuid, first->node ? first->node->details->uname : "[none]",
                     first->flags, first_flags, then->uuid, then->flags);
    }

    return changed;
}

void
native_rsc_location(resource_t * rsc, rsc_to_node_t * constraint)
{
    GListPtr gIter = NULL;
    GHashTableIter iter;
    node_t *node = NULL;

    if (constraint == NULL) {
        pe_err("Constraint is NULL");
        return;

    } else if (rsc == NULL) {
        pe_err("LHS of rsc_to_node (%s) is NULL", constraint->id);
        return;
    }

    pe_rsc_trace(rsc, "Applying %s (%s) to %s", constraint->id,
                 role2text(constraint->role_filter), rsc->id);

    /* take "lifetime" into account */
    if (constraint->role_filter > RSC_ROLE_UNKNOWN && constraint->role_filter != rsc->next_role) {
        pe_rsc_debug(rsc, "Constraint (%s) is not active (role : %s vs. %s)",
                     constraint->id, role2text(constraint->role_filter), role2text(rsc->next_role));
        return;

    } else if (is_active(constraint) == FALSE) {
        pe_rsc_trace(rsc, "Constraint (%s) is not active", constraint->id);
        return;
    }

    if (constraint->node_list_rh == NULL) {
        pe_rsc_trace(rsc, "RHS of constraint %s is NULL", constraint->id);
        return;
    }

    for (gIter = constraint->node_list_rh; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;
        node_t *other_node = NULL;

        other_node = (node_t *) pe_hash_table_lookup(rsc->allowed_nodes, node->details->id);

        if (other_node != NULL) {
            pe_rsc_trace(rsc, "%s + %s: %d + %d",
                         node->details->uname,
                         other_node->details->uname, node->weight, other_node->weight);
            other_node->weight = merge_weights(other_node->weight, node->weight);

        } else {
            node_t *new_node = node_copy(node);

            g_hash_table_insert(rsc->allowed_nodes, (gpointer) new_node->details->id, new_node);
        }
    }

    g_hash_table_iter_init(&iter, rsc->allowed_nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
        pe_rsc_trace(rsc, "%s + %s : %d", rsc->id, node->details->uname, node->weight);
    }
}

void
native_expand(resource_t * rsc, pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;

    pe_rsc_trace(rsc, "Processing actions from %s", rsc->id);

    for (gIter = rsc->actions; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;

        crm_trace("processing action %d for rsc=%s", action->id, rsc->id);
        graph_element_from_action(action, data_set);
    }

    for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        child_rsc->cmds->expand(child_rsc, data_set);
    }
}

void
#define log_change(fmt, args...)  do {          \
        if(terminal) {                          \
            printf(" * "fmt"\n", ##args);       \
        } else {                                \
            crm_notice(fmt, ##args);            \
        }                                       \
    } while(0)
LogActions(resource_t * rsc, pe_working_set_t * data_set, gboolean terminal)
{
    node_t *next = NULL;
    node_t *current = NULL;

    action_t *stop = NULL;
    action_t *start = NULL;
    action_t *demote = NULL;
    action_t *promote = NULL;

    char *key = NULL;
    gboolean moving = FALSE;
    GListPtr possible_matches = NULL;

    if (rsc->children) {
        GListPtr gIter = NULL;

        for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
            resource_t *child_rsc = (resource_t *) gIter->data;

            LogActions(child_rsc, data_set, terminal);
        }
        return;
    }

    next = rsc->allocated_to;
    if (rsc->running_on) {
        if (g_list_length(rsc->running_on) > 1 && rsc->partial_migration_source) {
            current = rsc->partial_migration_source;
        } else {
            current = rsc->running_on->data;
        }

        if (rsc->role == RSC_ROLE_STOPPED) {
            /*
             * This can occur when resources are being recovered
             * We fiddle with the current role in native_create_actions()
             */
            rsc->role = RSC_ROLE_STARTED;
        }
    }

    if (current == NULL && is_set(rsc->flags, pe_rsc_orphan)) {
        /* Don't log stopped orphans */
        return;
    }

    if (is_not_set(rsc->flags, pe_rsc_managed)
        || (current == NULL && next == NULL)) {
        pe_rsc_info(rsc, "Leave   %s\t(%s%s)",
                    rsc->id, role2text(rsc->role), is_not_set(rsc->flags,
                                                              pe_rsc_managed) ? " unmanaged" : "");
        return;
    }

    if (current != NULL && next != NULL && safe_str_neq(current->details->id, next->details->id)) {
        moving = TRUE;
    }

    key = start_key(rsc);
    possible_matches = find_actions(rsc->actions, key, next);
    free(key);
    if (possible_matches) {
        start = possible_matches->data;
        g_list_free(possible_matches);
    }

    key = stop_key(rsc);
    possible_matches = find_actions(rsc->actions, key, next);
    free(key);
    if (possible_matches) {
        stop = possible_matches->data;
        g_list_free(possible_matches);
    }

    key = promote_key(rsc);
    possible_matches = find_actions(rsc->actions, key, next);
    free(key);
    if (possible_matches) {
        promote = possible_matches->data;
        g_list_free(possible_matches);
    }

    key = demote_key(rsc);
    possible_matches = find_actions(rsc->actions, key, next);
    free(key);
    if (possible_matches) {
        demote = possible_matches->data;
        g_list_free(possible_matches);
    }

    if (rsc->role == rsc->next_role) {
        key = generate_op_key(rsc->id, RSC_MIGRATED, 0);
        possible_matches = find_actions(rsc->actions, key, next);
        free(key);

        CRM_CHECK(next != NULL,);
        if (next == NULL) {
        } else if (possible_matches && current) {
            log_change("Migrate %s\t(%s %s -> %s)",
                       rsc->id, role2text(rsc->role), current->details->uname,
                       next->details->uname);
            g_list_free(possible_matches);

        } else if (is_set(rsc->flags, pe_rsc_reload)) {
            log_change("Reload  %s\t(%s %s)", rsc->id, role2text(rsc->role), next->details->uname);

        } else if (start == NULL || is_set(start->flags, pe_action_optional)) {
            pe_rsc_info(rsc, "Leave   %s\t(%s %s)", rsc->id, role2text(rsc->role),
                        next->details->uname);

        } else if (start && is_set(start->flags, pe_action_runnable) == FALSE) {
            log_change("Stop    %s\t(%s %s)", rsc->id, role2text(rsc->role), next->details->uname);

        } else if (moving && current) {
            log_change("%s %s\t(%s %s -> %s)",
                       is_set(rsc->flags, pe_rsc_failed) ? "Recover" : "Move   ",
                       rsc->id, role2text(rsc->role),
                       current->details->uname, next->details->uname);

        } else if (is_set(rsc->flags, pe_rsc_failed)) {
            log_change("Recover %s\t(%s %s)", rsc->id, role2text(rsc->role), next->details->uname);

        } else {
            log_change("Restart %s\t(%s %s)", rsc->id, role2text(rsc->role), next->details->uname);
        }

        return;
    }

    if (rsc->role > RSC_ROLE_SLAVE && rsc->role > rsc->next_role) {
        CRM_CHECK(current != NULL,);
        if (current != NULL) {
            gboolean allowed = FALSE;

            if (demote != NULL && (demote->flags & pe_action_runnable)) {
                allowed = TRUE;
            }

            log_change("Demote  %s\t(%s -> %s %s%s)",
                       rsc->id,
                       role2text(rsc->role),
                       role2text(rsc->next_role),
                       current->details->uname, allowed ? "" : " - blocked");

            if (stop != NULL && is_not_set(stop->flags, pe_action_optional)
                && rsc->next_role > RSC_ROLE_STOPPED) {
                if (is_set(rsc->flags, pe_rsc_failed)) {
                    log_change("Recover %s\t(%s %s)",
                               rsc->id, role2text(rsc->role), next->details->uname);

                } else if (is_set(rsc->flags, pe_rsc_reload)) {
                    log_change("Reload  %s\t(%s %s)", rsc->id, role2text(rsc->role),
                               next->details->uname);

                } else {
                    log_change("Restart %s\t(%s %s)",
                               rsc->id, role2text(rsc->next_role), next->details->uname);
                }
            }
        }

    } else if (rsc->next_role == RSC_ROLE_STOPPED) {
        GListPtr gIter = NULL;

        CRM_CHECK(current != NULL,);

        key = stop_key(rsc);
        for (gIter = rsc->running_on; gIter != NULL; gIter = gIter->next) {
            node_t *node = (node_t *) gIter->data;
            action_t *stop_op = NULL;
            gboolean allowed = FALSE;

            possible_matches = find_actions(rsc->actions, key, node);
            if (possible_matches) {
                stop_op = possible_matches->data;
                g_list_free(possible_matches);
            }

            if (stop_op && (stop_op->flags & pe_action_runnable)) {
                allowed = TRUE;
            }

            log_change("Stop    %s\t(%s%s)", rsc->id, node->details->uname,
                       allowed ? "" : " - blocked");
        }

        free(key);
    }

    if (moving) {
        log_change("Move    %s\t(%s %s -> %s)",
                   rsc->id, role2text(rsc->next_role), current->details->uname,
                   next->details->uname);
    }

    if (rsc->role == RSC_ROLE_STOPPED) {
        gboolean allowed = FALSE;

        if (start && (start->flags & pe_action_runnable)) {
            allowed = TRUE;
        }

        CRM_CHECK(next != NULL,);
        if (next != NULL) {
            log_change("Start   %s\t(%s%s)", rsc->id, next->details->uname,
                       allowed ? "" : " - blocked");
        }
        if (allowed == FALSE) {
            return;
        }
    }

    if (rsc->next_role > RSC_ROLE_SLAVE && rsc->role < rsc->next_role) {
        gboolean allowed = FALSE;

        CRM_CHECK(next != NULL,);
        if (stop != NULL && is_not_set(stop->flags, pe_action_optional)
            && rsc->role > RSC_ROLE_STOPPED) {
            if (is_set(rsc->flags, pe_rsc_failed)) {
                log_change("Recover %s\t(%s %s)",
                           rsc->id, role2text(rsc->role), next->details->uname);

            } else if (is_set(rsc->flags, pe_rsc_reload)) {
                log_change("Reload  %s\t(%s %s)", rsc->id, role2text(rsc->role),
                           next->details->uname);

            } else {
                log_change("Restart %s\t(%s %s)",
                           rsc->id, role2text(rsc->role), next->details->uname);
            }
        }

        if (promote && (promote->flags & pe_action_runnable)) {
            allowed = TRUE;
        }

        log_change("Promote %s\t(%s -> %s %s%s)",
                   rsc->id,
                   role2text(rsc->role),
                   role2text(rsc->next_role), next->details->uname, allowed ? "" : " - blocked");
    }
}

gboolean
StopRsc(resource_t * rsc, node_t * next, gboolean optional, pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;

    pe_rsc_trace(rsc, "%s", rsc->id);

    for (gIter = rsc->running_on; gIter != NULL; gIter = gIter->next) {
        node_t *current = (node_t *) gIter->data;
        action_t *stop;

        if (rsc->partial_migration_target) {
            if (rsc->partial_migration_target->details == current->details) {
                pe_rsc_trace(rsc, "Filtered %s -> %s %s", current->details->uname,
                             next->details->uname, rsc->id);
                continue;
            } else {
                pe_rsc_trace(rsc, "Forced on %s %s", current->details->uname, rsc->id);
                optional = FALSE;
            }
        }

        pe_rsc_trace(rsc, "%s on %s", rsc->id, current->details->uname);
        stop = stop_action(rsc, current, optional);

        if (is_not_set(rsc->flags, pe_rsc_managed)) {
            update_action_flags(stop, pe_action_runnable | pe_action_clear);
        }

        if (is_set(data_set->flags, pe_flag_remove_after_stop)) {
            DeleteRsc(rsc, current, optional, data_set);
        }
    }

    return TRUE;
}

gboolean
StartRsc(resource_t * rsc, node_t * next, gboolean optional, pe_working_set_t * data_set)
{
    action_t *start = NULL;

    pe_rsc_trace(rsc, "%s on %s %d", rsc->id, next ? next->details->uname : "N/A", optional);
    start = start_action(rsc, next, TRUE);
    if (is_set(start->flags, pe_action_runnable) && optional == FALSE) {
        update_action_flags(start, pe_action_optional | pe_action_clear);
    }
    return TRUE;
}

gboolean
PromoteRsc(resource_t * rsc, node_t * next, gboolean optional, pe_working_set_t * data_set)
{
    char *key = NULL;
    GListPtr gIter = NULL;
    gboolean runnable = TRUE;
    GListPtr action_list = NULL;

    pe_rsc_trace(rsc, "%s on %s", rsc->id, next ? next->details->uname : "N/A");

    CRM_CHECK(next != NULL, return FALSE);

    key = start_key(rsc);
    action_list = find_actions_exact(rsc->actions, key, next);
    free(key);

    for (gIter = action_list; gIter != NULL; gIter = gIter->next) {
        action_t *start = (action_t *) gIter->data;

        if (is_set(start->flags, pe_action_runnable) == FALSE) {
            runnable = FALSE;
        }
    }
    g_list_free(action_list);

    if (runnable) {
        promote_action(rsc, next, optional);
        return TRUE;
    }

    pe_rsc_debug(rsc, "%s\tPromote %s (canceled)", next->details->uname, rsc->id);

    key = promote_key(rsc);
    action_list = find_actions_exact(rsc->actions, key, next);
    free(key);

    for (gIter = action_list; gIter != NULL; gIter = gIter->next) {
        action_t *promote = (action_t *) gIter->data;

        update_action_flags(promote, pe_action_runnable | pe_action_clear);
    }

    g_list_free(action_list);
    return TRUE;
}

gboolean
DemoteRsc(resource_t * rsc, node_t * next, gboolean optional, pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;

    pe_rsc_trace(rsc, "%s", rsc->id);

/* 	CRM_CHECK(rsc->next_role == RSC_ROLE_SLAVE, return FALSE); */
    for (gIter = rsc->running_on; gIter != NULL; gIter = gIter->next) {
        node_t *current = (node_t *) gIter->data;

        pe_rsc_trace(rsc, "%s on %s", rsc->id, next ? next->details->uname : "N/A");
        demote_action(rsc, current, optional);
    }
    return TRUE;
}

gboolean
RoleError(resource_t * rsc, node_t * next, gboolean optional, pe_working_set_t * data_set)
{
    crm_err("%s on %s", rsc->id, next ? next->details->uname : "N/A");
    CRM_CHECK(FALSE, return FALSE);
    return FALSE;
}

gboolean
NullOp(resource_t * rsc, node_t * next, gboolean optional, pe_working_set_t * data_set)
{
    pe_rsc_trace(rsc, "%s", rsc->id);
    return FALSE;
}

gboolean
DeleteRsc(resource_t * rsc, node_t * node, gboolean optional, pe_working_set_t * data_set)
{
    if (is_set(rsc->flags, pe_rsc_failed)) {
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

    new_rsc_order(rsc, RSC_STOP, rsc, RSC_DELETE,
                  optional ? pe_order_implies_then : pe_order_optional, data_set);

    new_rsc_order(rsc, RSC_DELETE, rsc, RSC_START,
                  optional ? pe_order_implies_then : pe_order_optional, data_set);

    return TRUE;
}

#include <../lib/pengine/unpack.h>
#define set_char(x) last_rsc_id[lpc] = x; complete = TRUE;
static char *
increment_clone(char *last_rsc_id)
{
    int lpc = 0;
    int len = 0;
    char *tmp = NULL;
    gboolean complete = FALSE;

    CRM_CHECK(last_rsc_id != NULL, return NULL);
    if (last_rsc_id != NULL) {
        len = strlen(last_rsc_id);
    }

    lpc = len - 1;
    while (complete == FALSE && lpc > 0) {
        switch (last_rsc_id[lpc]) {
            case 0:
                lpc--;
                break;
            case '0':
                set_char('1');
                break;
            case '1':
                set_char('2');
                break;
            case '2':
                set_char('3');
                break;
            case '3':
                set_char('4');
                break;
            case '4':
                set_char('5');
                break;
            case '5':
                set_char('6');
                break;
            case '6':
                set_char('7');
                break;
            case '7':
                set_char('8');
                break;
            case '8':
                set_char('9');
                break;
            case '9':
                last_rsc_id[lpc] = '0';
                lpc--;
                break;
            case ':':
                tmp = last_rsc_id;
                last_rsc_id = calloc(1, len + 2);
                memcpy(last_rsc_id, tmp, len);
                last_rsc_id[++lpc] = '1';
                last_rsc_id[len] = '0';
                last_rsc_id[len + 1] = 0;
                complete = TRUE;
                free(tmp);
                break;
            default:
                crm_err("Unexpected char: %c (%d)", last_rsc_id[lpc], lpc);
                return NULL;
                break;
        }
    }
    return last_rsc_id;
}

static node_t *
probe_grouped_clone(resource_t * rsc, node_t * node, pe_working_set_t * data_set)
{
    node_t *running = NULL;
    resource_t *top = uber_parent(rsc);

    if (running == NULL && is_set(top->flags, pe_rsc_unique) == FALSE) {
        /* Annoyingly we also need to check any other clone instances
         * Clumsy, but it will work.
         *
         * An alternative would be to update known_on for every peer
         * during process_rsc_state()
         *
         * This code desperately needs optimization
         * ptest -x with 100 nodes, 100 clones and clone-max=10:
         *   No probes                          O(25s)
         *   Detection without clone loop               O(3m)
         *   Detection with clone loop                  O(8m)

         ptest[32211]: 2010/02/18_14:27:55 CRIT: stage5: Probing for unknown resources
         ptest[32211]: 2010/02/18_14:33:39 CRIT: stage5: Done
         ptest[32211]: 2010/02/18_14:35:05 CRIT: stage7: Updating action states
         ptest[32211]: 2010/02/18_14:35:05 CRIT: stage7: Done

         */
        char *clone_id = clone_zero(rsc->id);
        resource_t *peer = pe_find_resource(top->children, clone_id);

        while (peer && running == NULL) {
            running = pe_hash_table_lookup(peer->known_on, node->details->id);
            if (running != NULL) {
                /* we already know the status of the resource on this node */
                pe_rsc_trace(rsc, "Skipping active clone: %s", rsc->id);
                free(clone_id);
                return running;
            }
            clone_id = increment_clone(clone_id);
            peer = pe_find_resource(data_set->resources, clone_id);
        }

        free(clone_id);
    }
    return running;
}

gboolean
native_create_probe(resource_t * rsc, node_t * node, action_t * complete,
                    gboolean force, pe_working_set_t * data_set)
{
    char *key = NULL;
    action_t *probe = NULL;
    node_t *running = NULL;
    resource_t *top = uber_parent(rsc);

    static const char *rc_master = NULL;
    static const char *rc_inactive = NULL;

    if (rc_inactive == NULL) {
        rc_inactive = crm_itoa(PCMK_EXECRA_NOT_RUNNING);
        rc_master = crm_itoa(PCMK_EXECRA_RUNNING_MASTER);
    }

    CRM_CHECK(node != NULL, return FALSE);
    if (force == FALSE && is_not_set(data_set->flags, pe_flag_startup_probes)) {
        pe_rsc_trace(rsc, "Skipping active resource detection for %s", rsc->id);
        return FALSE;
    }

    if (rsc->children) {
        GListPtr gIter = NULL;
        gboolean any_created = FALSE;

        for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
            resource_t *child_rsc = (resource_t *) gIter->data;

            any_created = child_rsc->cmds->create_probe(child_rsc, node, complete, force, data_set)
                || any_created;
        }

        return any_created;

    } else if (rsc->container && rsc->is_remote_node == FALSE) {
        pe_rsc_trace(rsc, "Skipping %s: it is within container %s", rsc->id, rsc->container->id);
        return FALSE;
    }

    if (is_set(rsc->flags, pe_rsc_orphan)) {
        pe_rsc_trace(rsc, "Skipping orphan: %s", rsc->id);
        return FALSE;
    }

    running = g_hash_table_lookup(rsc->known_on, node->details->id);
    if (running == NULL && is_set(rsc->flags, pe_rsc_unique) == FALSE) {
        /* Anonymous clones */
        if (rsc->parent == top) {
            running = g_hash_table_lookup(rsc->parent->known_on, node->details->id);

        } else {
            /* Grouped anonymous clones need extra special handling */
            running = probe_grouped_clone(rsc, node, data_set);
        }
    }

    if (force == FALSE && running != NULL) {
        /* we already know the status of the resource on this node */
        pe_rsc_trace(rsc, "Skipping active: %s on %s", rsc->id, node->details->uname);
        return FALSE;
    }

    key = generate_op_key(rsc->id, RSC_STATUS, 0);
    probe = custom_action(rsc, key, RSC_STATUS, node, FALSE, TRUE, data_set);
    update_action_flags(probe, pe_action_optional | pe_action_clear);

    /* Check if the node needs to be unfenced first */
    if (is_set(rsc->flags, pe_rsc_needs_unfencing)) {
        action_t *unfence = pe_fence_op(node, "on", data_set);

        crm_notice("Unfencing %s for %s", node->details->uname, rsc->id);
        order_actions(unfence, probe, pe_order_implies_then);

        /* The lack of ordering constraints on STONITH_UP would
         * traditionally mean unfencing is initiated /before/ the
         * devices are started.
         *
         * However this is a non-issue as stonithd is now smart
         * enough to be able to use devices directly from the cib
         */
    }

    /*
     * We need to know if it's running_on (not just known_on) this node
     * to correctly determine the target rc.
     */
    running = pe_find_node_id(rsc->running_on, node->details->id);
    if (running == NULL) {
        add_hash_param(probe->meta, XML_ATTR_TE_TARGET_RC, rc_inactive);

    } else if (rsc->role == RSC_ROLE_MASTER) {
        add_hash_param(probe->meta, XML_ATTR_TE_TARGET_RC, rc_master);
    }

    pe_rsc_debug(rsc, "Probing %s on %s (%s)", rsc->id, node->details->uname, role2text(rsc->role));
    order_actions(probe, complete, pe_order_implies_then);

    return TRUE;
}

static void
native_start_constraints(resource_t * rsc, action_t * stonith_op, gboolean is_stonith,
                         pe_working_set_t * data_set)
{
    node_t *target = stonith_op ? stonith_op->node : NULL;

    GListPtr gIter = NULL;
    action_t *all_stopped = get_pseudo_op(ALL_STOPPED, data_set);
    action_t *stonith_done = get_pseudo_op(STONITH_DONE, data_set);

    for (gIter = rsc->actions; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;

        if (action->needs == rsc_req_stonith) {
            order_actions(stonith_done, action, pe_order_optional);

        } else if (target != NULL && safe_str_eq(action->task, RSC_START)
                   && NULL == pe_hash_table_lookup(rsc->known_on, target->details->id)) {
            /* if known == NULL, then we dont know if
             *   the resource is active on the node
             *   we're about to shoot
             *
             * in this case, regardless of action->needs,
             *   the only safe option is to wait until
             *   the node is shot before doing anything
             *   to with the resource
             *
             * its analogous to waiting for all the probes
             *   for rscX to complete before starting rscX
             *
             * the most likely explaination is that the
             *   DC died and took its status with it
             */

            pe_rsc_debug(rsc, "Ordering %s after %s recovery", action->uuid,
                         target->details->uname);
            order_actions(all_stopped, action, pe_order_optional | pe_order_runnable_left);
        }
    }
}

static void
native_stop_constraints(resource_t * rsc, action_t * stonith_op, gboolean is_stonith,
                        pe_working_set_t * data_set)
{
    char *key = NULL;
    GListPtr gIter = NULL;
    GListPtr action_list = NULL;
    resource_t *top = uber_parent(rsc);

    key = stop_key(rsc);
    action_list = find_actions(rsc->actions, key, stonith_op->node);
    free(key);

    /* add the stonith OP as a stop pre-req and the mark the stop
     * as a pseudo op - since its now redundant
     */

    for (gIter = action_list; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;

        if (action->node->details->online
            && action->node->details->unclean == FALSE && is_set(rsc->flags, pe_rsc_failed)) {
            continue;
        }

        if (is_set(rsc->flags, pe_rsc_failed)) {
            crm_notice("Stop of failed resource %s is"
                       " implicit after %s is fenced", rsc->id, action->node->details->uname);
        } else {
            crm_info("%s is implicit after %s is fenced",
                     action->uuid, action->node->details->uname);
        }

        /* the stop would never complete and is
         * now implied by the stonith operation
         */
        update_action_flags(action, pe_action_pseudo);
        update_action_flags(action, pe_action_runnable);
        update_action_flags(action, pe_action_implied_by_stonith);

        {
            action_t *parent_stop = find_first_action(top->actions, NULL, RSC_STOP, NULL);

            order_actions(stonith_op, action, pe_order_optional);
            order_actions(stonith_op, parent_stop, pe_order_optional);
        }

        if (is_set(rsc->flags, pe_rsc_notify)) {
            /* Create a second notification that will be delivered
             *   immediately after the node is fenced
             *
             * Basic problem:
             * - C is a clone active on the node to be shot and stopping on another
             * - R is a resource that depends on C
             *
             * + C.stop depends on R.stop
             * + C.stopped depends on STONITH
             * + C.notify depends on C.stopped
             * + C.healthy depends on C.notify
             * + R.stop depends on C.healthy
             *
             * The extra notification here changes
             *  + C.healthy depends on C.notify
             * into:
             *  + C.healthy depends on C.notify'
             *  + C.notify' depends on STONITH'
             * thus breaking the loop
             */
            notify_data_t *n_data =
                create_notification_boundaries(rsc, RSC_STOP, NULL, stonith_op, data_set);
            crm_info("Creating secondary notification for %s", action->uuid);

            collect_notification_data(rsc, TRUE, FALSE, n_data);
            g_hash_table_insert(n_data->keys, strdup("notify_stop_resource"), strdup(rsc->id));
            g_hash_table_insert(n_data->keys, strdup("notify_stop_uname"),
                                strdup(action->node->details->uname));
            create_notifications(uber_parent(rsc), n_data, data_set);
            free_notification_data(n_data);
        }

/* From Bug #1601, successful fencing must be an input to a failed resources stop action.

   However given group(rA, rB) running on nodeX and B.stop has failed,
   A := stop healthy resource (rA.stop)
   B := stop failed resource (pseudo operation B.stop)
   C := stonith nodeX
   A requires B, B requires C, C requires A
   This loop would prevent the cluster from making progress.

   This block creates the "C requires A" dependency and therefore must (at least
   for now) be disabled.

   Instead, run the block above and treat all resources on nodeX as B would be
   (marked as a pseudo op depending on the STONITH).

   TODO: Break the "A requires B" dependency in update_action() and re-enable this block

   } else if(is_stonith == FALSE) {
   crm_info("Moving healthy resource %s"
   " off %s before fencing",
   rsc->id, node->details->uname);

   * stop healthy resources before the
   * stonith op
   *
   custom_action_order(
   rsc, stop_key(rsc), NULL,
   NULL,strdup(CRM_OP_FENCE),stonith_op,
   pe_order_optional, data_set);
*/
    }

    g_list_free(action_list);

    key = demote_key(rsc);
    action_list = find_actions(rsc->actions, key, stonith_op->node);
    free(key);

    for (gIter = action_list; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;

        if (action->node->details->online == FALSE || action->node->details->unclean == TRUE
            || is_set(rsc->flags, pe_rsc_failed)) {
            if (is_set(rsc->flags, pe_rsc_failed)) {
                pe_rsc_info(rsc, "Demote of failed resource %s is"
                            " implict after %s is fenced", rsc->id, action->node->details->uname);
            } else {
                pe_rsc_info(rsc, "%s is implicit after %s is fenced",
                            action->uuid, action->node->details->uname);
            }
            /* the stop would never complete and is
             * now implied by the stonith operation
             */
            crm_trace("here - 1");
            update_action_flags(action, pe_action_pseudo);
            update_action_flags(action, pe_action_runnable);
            if (is_stonith == FALSE) {
                order_actions(stonith_op, action, pe_order_optional);
            }
        }
    }

    g_list_free(action_list);
}

void
rsc_stonith_ordering(resource_t * rsc, action_t * stonith_op, pe_working_set_t * data_set)
{
    gboolean is_stonith = FALSE;

    if (rsc->children) {
        GListPtr gIter = NULL;

        for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
            resource_t *child_rsc = (resource_t *) gIter->data;

            rsc_stonith_ordering(child_rsc, stonith_op, data_set);
        }
        return;
    }

    if (is_not_set(rsc->flags, pe_rsc_managed)) {
        pe_rsc_trace(rsc, "Skipping fencing constraints for unmanaged resource: %s", rsc->id);
        return;
    }

    /* Start constraints */
    native_start_constraints(rsc, stonith_op, is_stonith, data_set);

    /* Stop constraints */
    if (stonith_op) {
        native_stop_constraints(rsc, stonith_op, is_stonith, data_set);
    }
}

enum stack_activity {
    stack_stable = 0,
    stack_starting = 1,
    stack_stopping = 2,
    stack_middle = 4,
};

static enum stack_activity
find_clone_activity_on(resource_t * rsc, resource_t * target, node_t * node, const char *type)
{
    int mode = stack_stable;
    action_t *active = NULL;

    if (target->children) {
        GListPtr gIter = NULL;

        for (gIter = target->children; gIter != NULL; gIter = gIter->next) {
            resource_t *child = (resource_t *) gIter->data;

            mode |= find_clone_activity_on(rsc, child, node, type);
        }
        return mode;
    }

    active = find_first_action(target->actions, NULL, RSC_START, NULL);
    if (active && is_set(active->flags, pe_action_optional) == FALSE
        && is_set(active->flags, pe_action_pseudo) == FALSE) {
        pe_rsc_debug(rsc, "%s: found scheduled %s action (%s)", rsc->id, active->uuid, type);
        mode |= stack_starting;
    }

    active = find_first_action(target->actions, NULL, RSC_STOP, node);
    if (active && is_set(active->flags, pe_action_optional) == FALSE
        && is_set(active->flags, pe_action_pseudo) == FALSE) {
        pe_rsc_debug(rsc, "%s: found scheduled %s action (%s)", rsc->id, active->uuid, type);
        mode |= stack_stopping;
    }

    return mode;
}

static enum stack_activity
check_stack_element(resource_t * rsc, resource_t * other_rsc, const char *type)
{
    resource_t *other_p = uber_parent(other_rsc);

    if (other_rsc == NULL || other_rsc == rsc) {
        return stack_stable;

    } else if (other_p->variant == pe_native) {
        crm_notice("Cannot migrate %s due to dependency on %s (%s)", rsc->id, other_rsc->id, type);
        return stack_middle;

    } else if (other_rsc == rsc->parent) {
        int mode = 0;
        GListPtr gIter = NULL;

        for (gIter = other_rsc->rsc_cons; gIter != NULL; gIter = gIter->next) {
            rsc_colocation_t *constraint = (rsc_colocation_t *) gIter->data;

            if (constraint->score > 0) {
                mode |= check_stack_element(rsc, constraint->rsc_rh, type);
            }
        }
        return mode;

    } else if (other_p->variant == pe_group) {
        crm_notice("Cannot migrate %s due to dependency on group %s (%s)",
                   rsc->id, other_rsc->id, type);
        return stack_middle;

    }

    /* else: >= clone */
    /*

       ## Assumption
       A depends on clone(B)

       ## Resource Activity During Move

       N1          N2              N3
       ---             ---         ---
       t0  A.stop
       t1  B.stop                          B.stop
       t2                  B.start         B.start
       t3                  A.start

       ## Resource Activity During Migration

       N1          N2              N3
       ---             ---         ---
       t0                  B.start         B.start
       t1  A.stop (1)
       t2                  A.start (2)
       t3  B.stop                          B.stop

       Node 1: Rewritten to be a migrate-to operation
       Node 2: Rewritten to be a migrate-from operation

       # Constraints

       The following constraints already exist in the system.
       The 'ok' and 'fail' column refers to whether they still hold for migration.

       a) A.stop  -> A.start - ok
       b) B.stop  -> B.start - fail

       c) A.stop  -> B.stop  - ok
       d) B.start -> A.start - ok

       e) B.stop  -> A.start - fail
       f) A.stop  -> B.start - fail

       ## Scenarios
       B unchanged             - ok
       B stopping only         - fail - possible after fixing 'e'
       B starting only         - fail - possible after fixing 'f'
       B stoping and starting  - fail - constraint 'b' is unfixable
       B restarting only on N2 - fail - as-per previous only rarer

     */
    /* Only allow migration when the clone is either stable, only starting or only stopping */
    return find_clone_activity_on(rsc, other_rsc, NULL, type);
}

static gboolean
at_stack_bottom(resource_t * rsc)
{
    char *key = NULL;
    action_t *start = NULL;
    action_t *other = NULL;
    int mode = stack_stable;
    GListPtr action_list = NULL;
    GListPtr gIter = NULL;
    GHashTable *coloc_list = NULL;

    key = start_key(rsc);
    action_list = find_actions(rsc->actions, key, NULL);
    free(key);

    pe_rsc_trace(rsc, "%s: processing", rsc->id);
    CRM_CHECK(action_list != NULL, return FALSE);

    start = action_list->data;
    g_list_free(action_list);

    coloc_list = g_hash_table_new(crm_str_hash, g_str_equal);
    for (gIter = rsc->rsc_cons; gIter != NULL; gIter = gIter->next) {
        rsc_colocation_t *constraint = (rsc_colocation_t *) gIter->data;
        resource_t *target = constraint->rsc_rh;

        pe_rsc_trace(rsc, "Checking %s: %s == %s (%d)", constraint->id, rsc->id, target->id,
                     constraint->score);
        if (constraint->score > 0) {
            mode |= check_stack_element(rsc, target, "coloc");
            if (mode & stack_middle) {
                goto bail;

            } else if ((mode & stack_stopping) && (mode & stack_starting)) {
                crm_notice("Cannot migrate %s due to colocation activity (last was %s)",
                           rsc->id, target->id);
                goto bail;
            }
            g_hash_table_insert(coloc_list, target->id, target);
        }
    }

    for (gIter = start->actions_before; gIter != NULL; gIter = gIter->next) {
        action_wrapper_t *other_w = (action_wrapper_t *) gIter->data;

        other = other_w->action;

        if (other_w->type & pe_order_serialize_only) {
            pe_rsc_trace(rsc, "%s: depends on %s (serialize ordering)", rsc->id, other->uuid);
            continue;
        }

        pe_rsc_trace(rsc, "%s: Checking %s ordering", rsc->id, other->uuid);

        if(other->rsc == NULL) {
            /* No colocation involved */
            crm_trace("%s: No colocation for %s", rsc->id, other->uuid);
            continue;

        } else if (is_set(other->flags, pe_action_optional) == FALSE) {
            mode |= check_stack_element(rsc, other->rsc, "order");
            if ((mode & stack_middle) && g_hash_table_lookup(coloc_list, other->rsc->id)) {
                crm_trace("%s: Stack middle: %s", rsc->id, other->rsc->id);
                goto bail;

            } else if ((mode & stack_stopping) && (mode & stack_starting)) {
                crm_notice("Cannot migrate %s due to ordering activity (last was %s)",
                           rsc->id, other->rsc->id);
                goto bail;
            }
        }
    }

    g_hash_table_destroy(coloc_list);
    return TRUE;

  bail:
    g_hash_table_destroy(coloc_list);
    return FALSE;
}

static action_t *
get_first_named_action(resource_t * rsc, const char *action, gboolean only_valid, node_t * current)
{
    action_t *a = NULL;
    GListPtr action_list = NULL;
    char *key = generate_op_key(rsc->id, action, 0);

    action_list = find_actions(rsc->actions, key, current);

    if (action_list == NULL || action_list->data == NULL) {
        crm_trace("%s: no %s action", rsc->id, action);
        free(key);
        return NULL;
    }

    a = action_list->data;
    g_list_free(action_list);

    if (only_valid && is_set(a->flags, pe_action_pseudo)) {
        crm_trace("%s: pseudo", key);
        a = NULL;

    } else if (only_valid && is_not_set(a->flags, pe_action_runnable)) {
        crm_trace("%s: runnable", key);
        a = NULL;
    }

    free(key);
    return a;
}

static void
MigrateRsc(resource_t * rsc, action_t * stop, action_t * start, pe_working_set_t * data_set,
           gboolean partial)
{
    action_t *to = NULL;
    action_t *from = NULL;
    action_t *then = NULL;
    action_t *other = NULL;
    action_t *done = get_pseudo_op(STONITH_DONE, data_set);

    GListPtr gIter = NULL;
    const char *value = g_hash_table_lookup(rsc->meta, XML_OP_ATTR_ALLOW_MIGRATE);

    if (crm_is_true(value) == FALSE) {
        return;
    }

    if (rsc->next_role > RSC_ROLE_SLAVE) {
        pe_rsc_trace(rsc, "%s: resource role: role=%s", rsc->id, role2text(rsc->next_role));
        return;
    }

    if (start == NULL || stop == NULL) {
        pe_rsc_trace(rsc, "%s: not exists %p -> %p", rsc->id, stop, start);
        return;

    } else if (start->node == NULL || stop->node == NULL) {
        pe_rsc_trace(rsc, "%s: no node %p -> %p", rsc->id, stop->node, start->node);
        return;

    } else if (is_set(stop->flags, pe_action_optional)) {
        pe_rsc_trace(rsc, "%s: stop action", rsc->id);
        return;

    } else if (is_set(start->flags, pe_action_optional)) {
        pe_rsc_trace(rsc, "%s: start action", rsc->id);
        return;

    } else if (stop->node->details == start->node->details) {
        pe_rsc_trace(rsc, "%s: not moving %p -> %p", rsc->id, stop->node, start->node);
        return;

    } else if (at_stack_bottom(rsc) == FALSE) {
        pe_rsc_trace(rsc, "%s: not at stack bottom", rsc->id);
        return;
    }

    pe_rsc_trace(rsc, "%s %s -> %s", rsc->id, stop->node->details->uname,
                 start->node->details->uname);

    if (partial) {
        pe_rsc_info(rsc, "Completing partial migration of %s from %s to %s", rsc->id,
                    stop->node ? stop->node->details->uname : "unknown",
                    start->node ? start->node->details->uname : "unknown");
    } else {
        pe_rsc_info(rsc, "Migrating %s from %s to %s", rsc->id,
                    stop->node ? stop->node->details->uname : "unknown",
                    start->node ? start->node->details->uname : "unknown");
    }

    /* Preserve the stop to ensure the end state is sane on that node,
     * Make the start a pseudo op
     * Create migrate_to, have it depend on everything the stop did
     * Create migrate_from
     *  *-> migrate_to -> migrate_from -> stop -> start
     */

    update_action_flags(start, pe_action_pseudo);       /* easier than trying to delete it from the graph
                                                         * but perhaps we should have it run anyway
                                                         */

    if (!partial) {
        to = custom_action(rsc, generate_op_key(rsc->id, RSC_MIGRATE, 0), RSC_MIGRATE, stop->node,
                           FALSE, TRUE, data_set);

        for (gIter = rsc->dangling_migrations; gIter != NULL; gIter = gIter->next) {
            node_t *current = (node_t *) gIter->data;
            action_t *stop = stop_action(rsc, current, FALSE);

            order_actions(stop, to, pe_order_optional);
            pe_rsc_trace(rsc, "Ordering migration after cleanup of %s on %s", rsc->id,
                         current->details->uname);
        }
    }
    from = custom_action(rsc, generate_op_key(rsc->id, RSC_MIGRATED, 0), RSC_MIGRATED, start->node,
                         FALSE, TRUE, data_set);

    /* This is slightly sub-optimal if 'to' fails, but always
     * run both halves of the migration before terminating the
     * transition.
     *
     * This can be removed if/when we update unpack_rsc_op() to
     * 'correctly' handle partial migrations.
     *
     * Without this, we end up stopping both sides
     */
    from->priority = INFINITY;

    if (!partial) {
        order_actions(to, from, pe_order_optional);
        add_hash_param(to->meta, XML_LRM_ATTR_MIGRATE_SOURCE, stop->node->details->uname);
        add_hash_param(to->meta, XML_LRM_ATTR_MIGRATE_TARGET, start->node->details->uname);
    }

    then = to ? to : from;
    order_actions(from, stop, pe_order_optional);
    order_actions(done, then, pe_order_optional);
    add_hash_param(from->meta, XML_LRM_ATTR_MIGRATE_SOURCE, stop->node->details->uname);
    add_hash_param(from->meta, XML_LRM_ATTR_MIGRATE_TARGET, start->node->details->uname);

    /* Create the correct ordering ajustments based on find_clone_activity_on(); */

    for (gIter = rsc->rsc_cons; gIter != NULL; gIter = gIter->next) {
        rsc_colocation_t *constraint = (rsc_colocation_t *) gIter->data;
        resource_t *target = constraint->rsc_rh;

        pe_rsc_info(rsc, "Repairing %s: %s == %s (%d)", constraint->id, rsc->id, target->id,
                    constraint->score);

        if (constraint->score > 0) {
            int mode = check_stack_element(rsc, target, "coloc");
            action_t *clone_stop = find_first_action(target->actions, NULL, RSC_STOP, NULL);
            action_t *clone_start = find_first_action(target->actions, NULL, RSC_STARTED, NULL);

            CRM_ASSERT(clone_stop != NULL);
            CRM_ASSERT(clone_start != NULL);
            CRM_ASSERT((mode & stack_middle) == 0);
            CRM_ASSERT(((mode & stack_stopping) && (mode & stack_starting)) == 0);

            if (mode & stack_stopping) {
#if 0
                crm_debug("Creating %s.start -> %s.stop ordering", rsc->id, target->id);
                order_actions(from, clone_stop, pe_order_optional);
#endif
                GListPtr lpc2 = NULL;

                for (lpc2 = start->actions_before; lpc2 != NULL; lpc2 = lpc2->next) {
                    action_wrapper_t *other_w = (action_wrapper_t *) lpc2->data;

                    /* Needed if the clone's started pseudo-action ever gets printed in the graph */
                    if (other_w->action == clone_start) {
                        crm_debug("Breaking %s -> %s ordering", other_w->action->uuid, start->uuid);
                        other_w->type = pe_order_none;
                    }
                }

            } else if (mode & stack_starting) {
#if 0
                crm_debug("Creating %s.started -> %s.stop ordering", target->id, rsc->id);
                order_actions(clone_start, to, pe_order_optional);
#endif
                GListPtr lpc2 = NULL;

                for (lpc2 = clone_stop->actions_before; lpc2 != NULL; lpc2 = lpc2->next) {
                    action_wrapper_t *other_w = (action_wrapper_t *) lpc2->data;

                    /* Needed if the clone's stop pseudo-action ever gets printed in the graph */
                    if (other_w->action == stop) {
                        crm_debug("Breaking %s -> %s ordering", other_w->action->uuid,
                                  clone_stop->uuid);
                        other_w->type = pe_order_none;
                    }
                }
            }
        }
    }
#if 0
    /* Implied now that start/stop are not morphed into migrate ops */

    /* Anything that needed stop to complete, now also needs start to have completed */
    for (gIter = stop->actions_after; gIter != NULL; gIter = gIter->next) {
        action_wrapper_t *other_w = (action_wrapper_t *) gIter->data;

        other = other_w->action;
        if (is_set(other->flags, pe_action_optional) || other->rsc != NULL) {
            continue;
        }
        crm_debug("Ordering %s before %s (stop)", from->uuid, other->uuid);
        order_actions(from, other, other_w->type);
    }
#endif
    /* migrate 'then' action also needs anything that the stop needed to have completed too */
    for (gIter = stop->actions_before; gIter != NULL; gIter = gIter->next) {
        action_wrapper_t *other_w = (action_wrapper_t *) gIter->data;

        other = other_w->action;
        if (other->rsc == NULL) {
            /* nothing */

        } else if (is_set(other->flags, pe_action_optional) || other->rsc == rsc
                   || other->rsc == rsc->parent) {
            continue;
        }
        crm_debug("Ordering %s before %s (stop)", other_w->action->uuid, then->uuid);
        order_actions(other, then, other_w->type);
    }

    /* migrate 'then' action also needs anything that the start needed to have completed too */
    for (gIter = start->actions_before; gIter != NULL; gIter = gIter->next) {
        action_wrapper_t *other_w = (action_wrapper_t *) gIter->data;

        other = other_w->action;
        if (other->rsc == NULL) {
            /* nothing */
        } else if (is_set(other->flags, pe_action_optional) || other->rsc == rsc
                   || other->rsc == rsc->parent) {
            continue;
        }
        crm_debug("Ordering %s before %s (start)", other_w->action->uuid, then->uuid);
        order_actions(other, then, other_w->type);
    }
}

static void
ReloadRsc(resource_t * rsc, action_t * stop, action_t * start, pe_working_set_t * data_set)
{
    action_t *action = NULL;
    action_t *rewrite = NULL;

    if (is_not_set(rsc->flags, pe_rsc_try_reload)) {
        return;

    } else if (is_not_set(stop->flags, pe_action_optional)) {
        pe_rsc_trace(rsc, "%s: stop action", rsc->id);
        return;

    } else if (is_not_set(start->flags, pe_action_optional)) {
        pe_rsc_trace(rsc, "%s: start action", rsc->id);
        return;
    }

    pe_rsc_trace(rsc, "%s on %s", rsc->id, stop->node->details->uname);

    action = get_first_named_action(rsc, RSC_PROMOTE, TRUE, NULL);
    if (action && is_set(action->flags, pe_action_optional) == FALSE) {
        update_action_flags(action, pe_action_pseudo);
    }

    action = get_first_named_action(rsc, RSC_DEMOTE, TRUE, NULL);
    if (action && is_set(action->flags, pe_action_optional) == FALSE) {
        rewrite = action;
        update_action_flags(stop, pe_action_pseudo);

    } else {
        rewrite = start;
    }

    pe_rsc_info(rsc, "Rewriting %s of %s on %s as a reload",
                rewrite->task, rsc->id, stop->node->details->uname);
    set_bit(rsc->flags, pe_rsc_reload);
    update_action_flags(rewrite, pe_action_optional | pe_action_clear);

    free(rewrite->uuid);
    free(rewrite->task);
    rewrite->task = strdup("reload");
    rewrite->uuid = generate_op_key(rsc->id, rewrite->task, 0);
}

void
rsc_migrate_reload(resource_t * rsc, pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;
    action_t *stop = NULL;
    action_t *start = NULL;
    gboolean partial = FALSE;

    if (rsc->children) {
        for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
            resource_t *child_rsc = (resource_t *) gIter->data;

            rsc_migrate_reload(child_rsc, data_set);
        }
        return;

    } else if (rsc->variant > pe_native) {
        return;
    }

    pe_rsc_trace(rsc, "Processing %s", rsc->id);

    if (rsc->partial_migration_target) {
        start = get_first_named_action(rsc, RSC_START, TRUE, rsc->partial_migration_target);
        stop = get_first_named_action(rsc, RSC_STOP, TRUE, rsc->partial_migration_source);
        if (start && stop) {
            partial = TRUE;
        }
    }

    pe_rsc_trace(rsc, "%s %s %p", rsc->id, partial ? "partial" : "full", stop);

    if (!partial) {
        stop =
            get_first_named_action(rsc, RSC_STOP, TRUE,
                                   rsc->running_on ? rsc->running_on->data : NULL);
        start = get_first_named_action(rsc, RSC_START, TRUE, NULL);
    }

    if (is_not_set(rsc->flags, pe_rsc_managed)
        || is_set(rsc->flags, pe_rsc_failed)
        || is_set(rsc->flags, pe_rsc_start_pending)
        || rsc->next_role < RSC_ROLE_STARTED || ((g_list_length(rsc->running_on) != 1) && !partial)) {
        pe_rsc_trace(rsc, "%s: general resource state: flags=0x%.16llx", rsc->id, rsc->flags);
        return;
    }

    if (stop != NULL && is_set(stop->flags, pe_action_optional) && is_set(rsc->flags, pe_rsc_try_reload)) {
        ReloadRsc(rsc, stop, start, data_set);

    } else if (stop == NULL || is_not_set(stop->flags, pe_action_optional)) {
        MigrateRsc(rsc, stop, start, data_set, partial);
    }
}

void
native_append_meta(resource_t * rsc, xmlNode * xml)
{
    char *value = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_INCARNATION);

    if (value) {
        char *name = NULL;

        name = crm_meta_name(XML_RSC_ATTR_INCARNATION);
        crm_xml_add(xml, name, value);
        free(name);
    }
}

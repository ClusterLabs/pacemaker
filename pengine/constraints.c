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

#include <sys/param.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>


#include <glib.h>

#include <crm/pengine/status.h>
#include <pengine.h>
#include <allocate.h>
#include <utils.h>
#include <crm/pengine/rules.h>
#include <lib/pengine/utils.h>

enum pe_order_kind {
    pe_order_kind_optional,
    pe_order_kind_mandatory,
    pe_order_kind_serialize,
};

#define EXPAND_CONSTRAINT_IDREF(__set, __rsc, __name) do {				\
	__rsc = pe_find_resource(data_set->resources, __name);		\
	if(__rsc == NULL) {						\
	    crm_config_err("%s: No resource found for %s", __set, __name); \
	    return FALSE;						\
	}								\
    } while(0)

enum pe_ordering get_flags(const char *id, enum pe_order_kind kind,
                           const char *action_first, const char *action_then, gboolean invert);
enum pe_ordering get_asymmetrical_flags(enum pe_order_kind kind);

gboolean
unpack_constraints(xmlNode * xml_constraints, pe_working_set_t * data_set)
{
    xmlNode *xml_obj = NULL;
    xmlNode *lifetime = NULL;

    for (xml_obj = __xml_first_child(xml_constraints); xml_obj != NULL;
         xml_obj = __xml_next(xml_obj)) {
        const char *id = crm_element_value(xml_obj, XML_ATTR_ID);

        if (id == NULL) {
            crm_config_err("Constraint <%s...> must have an id", crm_element_name(xml_obj));
            continue;
        }

        crm_trace("Processing constraint %s %s", crm_element_name(xml_obj), id);

        lifetime = first_named_child(xml_obj, "lifetime");
        if (lifetime) {
            crm_config_warn("Support for the lifetime tag, used by %s, is deprecated."
                            " The rules it contains should instead be direct decendants of the constraint object",
                            id);
        }

        if (test_ruleset(lifetime, NULL, data_set->now) == FALSE) {
            crm_info("Constraint %s %s is not active", crm_element_name(xml_obj), id);

        } else if (safe_str_eq(XML_CONS_TAG_RSC_ORDER, crm_element_name(xml_obj))) {
            unpack_rsc_order(xml_obj, data_set);

        } else if (safe_str_eq(XML_CONS_TAG_RSC_DEPEND, crm_element_name(xml_obj))) {
            unpack_rsc_colocation(xml_obj, data_set);

        } else if (safe_str_eq(XML_CONS_TAG_RSC_LOCATION, crm_element_name(xml_obj))) {
            unpack_rsc_location(xml_obj, data_set);

        } else if (safe_str_eq(XML_CONS_TAG_RSC_TICKET, crm_element_name(xml_obj))) {
            unpack_rsc_ticket(xml_obj, data_set);

        } else {
            pe_err("Unsupported constraint type: %s", crm_element_name(xml_obj));
        }
    }

    return TRUE;
}

static const char *
invert_action(const char *action)
{
    if (safe_str_eq(action, RSC_START)) {
        return RSC_STOP;

    } else if (safe_str_eq(action, RSC_STOP)) {
        return RSC_START;

    } else if (safe_str_eq(action, RSC_PROMOTE)) {
        return RSC_DEMOTE;

    } else if (safe_str_eq(action, RSC_DEMOTE)) {
        return RSC_PROMOTE;

    } else if (safe_str_eq(action, RSC_PROMOTED)) {
        return RSC_DEMOTED;

    } else if (safe_str_eq(action, RSC_DEMOTED)) {
        return RSC_PROMOTED;

    } else if (safe_str_eq(action, RSC_STARTED)) {
        return RSC_STOPPED;

    } else if (safe_str_eq(action, RSC_STOPPED)) {
        return RSC_STARTED;
    }
    crm_config_warn("Unknown action: %s", action);
    return NULL;
}

static enum pe_order_kind
get_ordering_type(xmlNode * xml_obj)
{
    enum pe_order_kind kind_e = pe_order_kind_mandatory;
    const char *kind = crm_element_value(xml_obj, XML_ORDER_ATTR_KIND);

    if (kind == NULL) {
        const char *score = crm_element_value(xml_obj, XML_RULE_ATTR_SCORE);

        kind_e = pe_order_kind_mandatory;

        if (score) {
            int score_i = char2score(score);

            if (score_i == 0) {
                kind_e = pe_order_kind_optional;
            }

            /* } else if(rsc_then->variant == pe_native && rsc_first->variant > pe_group) { */
            /*     kind_e = pe_order_kind_optional; */
        }

    } else if (safe_str_eq(kind, "Mandatory")) {
        kind_e = pe_order_kind_mandatory;

    } else if (safe_str_eq(kind, "Optional")) {
        kind_e = pe_order_kind_optional;

    } else if (safe_str_eq(kind, "Serialize")) {
        kind_e = pe_order_kind_serialize;

    } else {
        const char *id = crm_element_value(xml_obj, XML_ATTR_ID);

        crm_config_err("Constraint %s: Unknown type '%s'", id, kind);
    }
    return kind_e;
}

static gboolean
contains_stonith(resource_t * rsc)
{
    GListPtr gIter = rsc->children;

    if (gIter == FALSE) {
        const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);

        if (safe_str_eq(class, "stonith")) {
            return TRUE;
        }
    }

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child = (resource_t *) gIter->data;

        if (contains_stonith(child)) {
            return TRUE;
        }
    }
    return FALSE;
}

static gboolean
unpack_simple_rsc_order(xmlNode * xml_obj, pe_working_set_t * data_set)
{
    int order_id = 0;
    resource_t *rsc_then = NULL;
    resource_t *rsc_first = NULL;
    gboolean invert_bool = TRUE;
    enum pe_order_kind kind = pe_order_kind_mandatory;
    enum pe_ordering cons_weight = pe_order_optional;

    const char *id_first = NULL;
    const char *id_then = NULL;
    const char *action_then = NULL;
    const char *action_first = NULL;
    const char *instance_then = NULL;
    const char *instance_first = NULL;

    const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
    const char *invert = crm_element_value(xml_obj, XML_CONS_ATTR_SYMMETRICAL);

    crm_str_to_boolean(invert, &invert_bool);

    if (xml_obj == NULL) {
        crm_config_err("No constraint object to process.");
        return FALSE;

    } else if (id == NULL) {
        crm_config_err("%s constraint must have an id", crm_element_name(xml_obj));
        return FALSE;
    }

    id_then = crm_element_value(xml_obj, XML_ORDER_ATTR_THEN);
    id_first = crm_element_value(xml_obj, XML_ORDER_ATTR_FIRST);

    action_then = crm_element_value(xml_obj, XML_ORDER_ATTR_THEN_ACTION);
    action_first = crm_element_value(xml_obj, XML_ORDER_ATTR_FIRST_ACTION);

    instance_then = crm_element_value(xml_obj, XML_ORDER_ATTR_THEN_INSTANCE);
    instance_first = crm_element_value(xml_obj, XML_ORDER_ATTR_FIRST_INSTANCE);

    if (action_first == NULL) {
        action_first = RSC_START;
    }
    if (action_then == NULL) {
        action_then = action_first;
    }

    if (id_then == NULL || id_first == NULL) {
        crm_config_err("Constraint %s needs two sides lh: %s rh: %s",
                       id, crm_str(id_then), crm_str(id_first));
        return FALSE;
    }

    rsc_then = pe_find_resource(data_set->resources, id_then);
    rsc_first = pe_find_resource(data_set->resources, id_first);

    if (rsc_then == NULL) {
        crm_config_err("Constraint %s: no resource found for name '%s'", id, id_then);
        return FALSE;

    } else if (rsc_first == NULL) {
        crm_config_err("Constraint %s: no resource found for name '%s'", id, id_first);
        return FALSE;

    } else if (instance_then && rsc_then->variant < pe_clone) {
        crm_config_err("Invalid constraint '%s':"
                       " Resource '%s' is not a clone but instance %s was requested",
                       id, id_then, instance_then);
        return FALSE;

    } else if (instance_first && rsc_first->variant < pe_clone) {
        crm_config_err("Invalid constraint '%s':"
                       " Resource '%s' is not a clone but instance %s was requested",
                       id, id_first, instance_first);
        return FALSE;
    }

    if (instance_then) {
        rsc_then = find_clone_instance(rsc_then, instance_then, data_set);
        if (rsc_then == NULL) {
            crm_config_warn("Invalid constraint '%s': No instance '%s' of '%s'", id, instance_then,
                            id_then);
            return FALSE;
        }
    }

    if (instance_first) {
        rsc_first = find_clone_instance(rsc_first, instance_first, data_set);
        if (rsc_first == NULL) {
            crm_config_warn("Invalid constraint '%s': No instance '%s' of '%s'", id, instance_first,
                            id_first);
            return FALSE;
        }
    }

    if (safe_str_eq(action_first, RSC_STOP) && contains_stonith(rsc_then)) {
        if (contains_stonith(rsc_first) == FALSE) {
            crm_config_err
                ("Constraint %s: Ordering STONITH resource (%s) to stop before %s is illegal", id,
                 rsc_first->id, rsc_then->id);
        }
        return FALSE;
    }

    cons_weight = pe_order_optional;
    kind = get_ordering_type(xml_obj);

    if (kind == pe_order_kind_optional && rsc_then->restart_type == pe_restart_restart) {
        crm_trace("Upgrade : recovery - implies right");
        cons_weight |= pe_order_implies_then;
    }

    if (invert_bool == FALSE) {
        cons_weight |= get_asymmetrical_flags(kind);
    } else {
        cons_weight |= get_flags(id, kind, action_first, action_then, FALSE);
    }
    order_id = new_rsc_order(rsc_first, action_first, rsc_then, action_then, cons_weight, data_set);

    crm_trace("order-%d (%s): %s_%s before %s_%s flags=0x%.6x",
                order_id, id, rsc_first->id, action_first, rsc_then->id, action_then, cons_weight);

    if (invert_bool == FALSE) {
        return TRUE;

    } else if (invert && kind == pe_order_kind_serialize) {
        crm_config_warn("Cannot invert serialized constraint set %s", id);
        return TRUE;

    } else if (kind == pe_order_kind_serialize) {
        return TRUE;
    }

    action_then = invert_action(action_then);
    action_first = invert_action(action_first);
    if (action_then == NULL || action_first == NULL) {
        crm_config_err("Cannot invert rsc_order constraint %s."
                       " Please specify the inverse manually.", id);
        return TRUE;
    }

    if (safe_str_eq(action_first, RSC_STOP) && contains_stonith(rsc_then)) {
        if (contains_stonith(rsc_first) == FALSE) {
            crm_config_err
                ("Constraint %s: Ordering STONITH resource (%s) to stop before %s is illegal", id,
                 rsc_first->id, rsc_then->id);
        }
        return FALSE;
    }

    cons_weight = pe_order_optional;
    if (kind == pe_order_kind_optional && rsc_then->restart_type == pe_restart_restart) {
        crm_trace("Upgrade : recovery - implies left");
        cons_weight |= pe_order_implies_first;
    }

    cons_weight |= get_flags(id, kind, action_first, action_then, TRUE);
    order_id = new_rsc_order(rsc_then, action_then, rsc_first, action_first, cons_weight, data_set);

    crm_trace("order-%d (%s): %s_%s before %s_%s flags=0x%.6x",
                order_id, id, rsc_then->id, action_then, rsc_first->id, action_first, cons_weight);

    return TRUE;
}

gboolean
unpack_rsc_location(xmlNode * xml_obj, pe_working_set_t * data_set)
{
    gboolean empty = TRUE;
    rsc_to_node_t *location = NULL;
    const char *id_lh = crm_element_value(xml_obj, "rsc");
    const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
    resource_t *rsc_lh = pe_find_resource(data_set->resources, id_lh);
    const char *node = crm_element_value(xml_obj, "node");
    const char *score = crm_element_value(xml_obj, XML_RULE_ATTR_SCORE);
    const char *domain = crm_element_value(xml_obj, XML_CIB_TAG_DOMAIN);
    const char *role = crm_element_value(xml_obj, XML_RULE_ATTR_ROLE);

    if (rsc_lh == NULL) {
        /* only a warn as BSC adds the constraint then the resource */
        crm_config_warn("No resource (con=%s, rsc=%s)", id, id_lh);
        return FALSE;
    }

    if (domain) {
        GListPtr nodes = g_hash_table_lookup(data_set->domains, domain);

        if (domain == NULL) {
            crm_config_err("Invalid constraint %s: Domain %s does not exist", id, domain);
            return FALSE;
        }

        location = rsc2node_new(id, rsc_lh, 0, NULL, data_set);
        location->node_list_rh = node_list_dup(nodes, FALSE, FALSE);

    } else if (node != NULL && score != NULL) {
        int score_i = char2score(score);
        node_t *match = pe_find_node(data_set->nodes, node);

        if (!match) {
            return FALSE;
        }
        location = rsc2node_new(id, rsc_lh, score_i, match, data_set);

    } else {
        xmlNode *rule_xml = NULL;

        for (rule_xml = __xml_first_child(xml_obj); rule_xml != NULL;
             rule_xml = __xml_next(rule_xml)) {
            if (crm_str_eq((const char *)rule_xml->name, XML_TAG_RULE, TRUE)) {
                empty = FALSE;
                crm_trace("Unpacking %s/%s", id, ID(rule_xml));
                generate_location_rule(rsc_lh, rule_xml, data_set);
            }
        }

        if (empty) {
            crm_config_err("Invalid location constraint %s:"
                           " rsc_location must contain at least one rule", ID(xml_obj));
        }
    }

    if (location && role) {
        if (text2role(role) == RSC_ROLE_UNKNOWN) {
            pe_err("Invalid constraint %s: Bad role %s", id, role);
            return FALSE;

        } else {
            location->role_filter = text2role(role);
            if (location->role_filter == RSC_ROLE_SLAVE) {
                /* Fold slave back into Started for simplicity
                 * At the point Slave location constraints are evaluated,
                 * all resources are still either stopped or started
                 */
                location->role_filter = RSC_ROLE_STARTED;
            }
        }
    }
    return TRUE;
}

static int
get_node_score(const char *rule, const char *score, gboolean raw, node_t * node)
{
    int score_f = 0;

    if (score == NULL) {
        pe_err("Rule %s: no score specified.  Assuming 0.", rule);

    } else if (raw) {
        score_f = char2score(score);

    } else {
        const char *attr_score = g_hash_table_lookup(node->details->attrs, score);

        if (attr_score == NULL) {
            crm_debug("Rule %s: node %s did not have a value for %s",
                      rule, node->details->uname, score);
            score_f = -INFINITY;

        } else {
            crm_debug("Rule %s: node %s had value %s for %s",
                      rule, node->details->uname, attr_score, score);
            score_f = char2score(attr_score);
        }
    }
    return score_f;
}

rsc_to_node_t *
generate_location_rule(resource_t * rsc, xmlNode * rule_xml, pe_working_set_t * data_set)
{
    const char *rule_id = NULL;
    const char *score = NULL;
    const char *boolean = NULL;
    const char *role = NULL;

    GListPtr gIter = NULL;
    GListPtr match_L = NULL;

    int score_f = 0;
    gboolean do_and = TRUE;
    gboolean accept = TRUE;
    gboolean raw_score = TRUE;

    rsc_to_node_t *location_rule = NULL;

    rule_xml = expand_idref(rule_xml, data_set->input);
    rule_id = crm_element_value(rule_xml, XML_ATTR_ID);
    boolean = crm_element_value(rule_xml, XML_RULE_ATTR_BOOLEAN_OP);
    role = crm_element_value(rule_xml, XML_RULE_ATTR_ROLE);

    crm_trace("Processing rule: %s", rule_id);

    if (role != NULL && text2role(role) == RSC_ROLE_UNKNOWN) {
        pe_err("Bad role specified for %s: %s", rule_id, role);
        return NULL;
    }

    score = crm_element_value(rule_xml, XML_RULE_ATTR_SCORE);
    if (score != NULL) {
        score_f = char2score(score);

    } else {
        score = crm_element_value(rule_xml, XML_RULE_ATTR_SCORE_ATTRIBUTE);
        if (score == NULL) {
            score = crm_element_value(rule_xml, XML_RULE_ATTR_SCORE_MANGLED);
        }
        if (score != NULL) {
            raw_score = FALSE;
        }
    }
    if (safe_str_eq(boolean, "or")) {
        do_and = FALSE;
    }

    location_rule = rsc2node_new(rule_id, rsc, 0, NULL, data_set);

    if (location_rule == NULL) {
        return NULL;
    }
    if (role != NULL) {
        crm_trace("Setting role filter: %s", role);
        location_rule->role_filter = text2role(role);
        if (location_rule->role_filter == RSC_ROLE_SLAVE) {
            /* Fold slave back into Started for simplicity
             * At the point Slave location constraints are evaluated,
             * all resources are still either stopped or started
             */
            location_rule->role_filter = RSC_ROLE_STARTED;
        }
    }
    if (do_and) {
        GListPtr gIter = NULL;

        match_L = node_list_dup(data_set->nodes, TRUE, FALSE);
        for (gIter = match_L; gIter != NULL; gIter = gIter->next) {
            node_t *node = (node_t *) gIter->data;

            node->weight = get_node_score(rule_id, score, raw_score, node);
        }
    }

    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;

        accept = test_rule(rule_xml, node->details->attrs, RSC_ROLE_UNKNOWN, data_set->now);

        crm_trace("Rule %s %s on %s", ID(rule_xml), accept ? "passed" : "failed",
                    node->details->uname);

        score_f = get_node_score(rule_id, score, raw_score, node);
/* 			if(accept && score_f == -INFINITY) { */
/* 				accept = FALSE; */
/* 			} */

        if (accept) {
            node_t *local = pe_find_node_id(match_L, node->details->id);

            if (local == NULL && do_and) {
                continue;

            } else if (local == NULL) {
                local = node_copy(node);
                match_L = g_list_append(match_L, local);
            }

            if (do_and == FALSE) {
                local->weight = merge_weights(local->weight, score_f);
            }
            crm_trace("node %s now has weight %d", node->details->uname, local->weight);

        } else if (do_and && !accept) {
            /* remove it */
            node_t *delete = pe_find_node_id(match_L, node->details->id);

            if (delete != NULL) {
                match_L = g_list_remove(match_L, delete);
                crm_trace("node %s did not match", node->details->uname);
            }
            free(delete);
        }
    }

    location_rule->node_list_rh = match_L;
    if (location_rule->node_list_rh == NULL) {
        crm_trace("No matching nodes for rule %s", rule_id);
        return NULL;
    }

    crm_trace("%s: %d nodes matched", rule_id, g_list_length(location_rule->node_list_rh));
    return location_rule;
}

static gint
sort_cons_priority_lh(gconstpointer a, gconstpointer b)
{
    const rsc_colocation_t *rsc_constraint1 = (const rsc_colocation_t *)a;
    const rsc_colocation_t *rsc_constraint2 = (const rsc_colocation_t *)b;

    if (a == NULL) {
        return 1;
    }
    if (b == NULL) {
        return -1;
    }

    CRM_ASSERT(rsc_constraint1->rsc_lh != NULL);
    CRM_ASSERT(rsc_constraint1->rsc_rh != NULL);

    if (rsc_constraint1->rsc_lh->priority > rsc_constraint2->rsc_lh->priority) {
        return -1;
    }

    if (rsc_constraint1->rsc_lh->priority < rsc_constraint2->rsc_lh->priority) {
        return 1;
    }

    return strcmp(rsc_constraint1->rsc_lh->id, rsc_constraint2->rsc_lh->id);
}

static gint
sort_cons_priority_rh(gconstpointer a, gconstpointer b)
{
    const rsc_colocation_t *rsc_constraint1 = (const rsc_colocation_t *)a;
    const rsc_colocation_t *rsc_constraint2 = (const rsc_colocation_t *)b;

    if (a == NULL) {
        return 1;
    }
    if (b == NULL) {
        return -1;
    }

    CRM_ASSERT(rsc_constraint1->rsc_lh != NULL);
    CRM_ASSERT(rsc_constraint1->rsc_rh != NULL);

    if (rsc_constraint1->rsc_rh->priority > rsc_constraint2->rsc_rh->priority) {
        return -1;
    }

    if (rsc_constraint1->rsc_rh->priority < rsc_constraint2->rsc_rh->priority) {
        return 1;
    }
    return strcmp(rsc_constraint1->rsc_rh->id, rsc_constraint2->rsc_rh->id);
}

gboolean
rsc_colocation_new(const char *id, const char *node_attr, int score,
                   resource_t * rsc_lh, resource_t * rsc_rh,
                   const char *state_lh, const char *state_rh, pe_working_set_t * data_set)
{
    rsc_colocation_t *new_con = NULL;

    if (rsc_lh == NULL) {
        crm_config_err("No resource found for LHS %s", id);
        return FALSE;

    } else if (rsc_rh == NULL) {
        crm_config_err("No resource found for RHS of %s", id);
        return FALSE;
    }

    new_con = calloc(1, sizeof(rsc_colocation_t));
    if (new_con == NULL) {
        return FALSE;
    }

    if (state_lh == NULL || safe_str_eq(state_lh, RSC_ROLE_STARTED_S)) {
        state_lh = RSC_ROLE_UNKNOWN_S;
    }

    if (state_rh == NULL || safe_str_eq(state_rh, RSC_ROLE_STARTED_S)) {
        state_rh = RSC_ROLE_UNKNOWN_S;
    }

    new_con->id = id;
    new_con->rsc_lh = rsc_lh;
    new_con->rsc_rh = rsc_rh;
    new_con->score = score;
    new_con->role_lh = text2role(state_lh);
    new_con->role_rh = text2role(state_rh);
    new_con->node_attribute = node_attr;

    if (node_attr == NULL) {
        node_attr = "#" XML_ATTR_UNAME;
    }

    crm_trace("%s ==> %s (%s %d)", rsc_lh->id, rsc_rh->id, node_attr, score);

    rsc_lh->rsc_cons = g_list_insert_sorted(rsc_lh->rsc_cons, new_con, sort_cons_priority_rh);

    rsc_rh->rsc_cons_lhs =
        g_list_insert_sorted(rsc_rh->rsc_cons_lhs, new_con, sort_cons_priority_lh);

    data_set->colocation_constraints = g_list_append(data_set->colocation_constraints, new_con);

    return TRUE;
}

/* LHS before RHS */
int
new_rsc_order(resource_t * lh_rsc, const char *lh_task,
              resource_t * rh_rsc, const char *rh_task,
              enum pe_ordering type, pe_working_set_t * data_set)
{
    char *lh_key = NULL;
    char *rh_key = NULL;

    CRM_CHECK(lh_rsc != NULL, return -1);
    CRM_CHECK(lh_task != NULL, return -1);
    CRM_CHECK(rh_rsc != NULL, return -1);
    CRM_CHECK(rh_task != NULL, return -1);

    lh_key = generate_op_key(lh_rsc->id, lh_task, 0);
    rh_key = generate_op_key(rh_rsc->id, rh_task, 0);

    return custom_action_order(lh_rsc, lh_key, NULL, rh_rsc, rh_key, NULL, type, data_set);
}

/* LHS before RHS */
int
custom_action_order(resource_t * lh_rsc, char *lh_action_task, action_t * lh_action,
                    resource_t * rh_rsc, char *rh_action_task, action_t * rh_action,
                    enum pe_ordering type, pe_working_set_t * data_set)
{
    order_constraint_t *order = NULL;

    if (lh_rsc == NULL && lh_action) {
        lh_rsc = lh_action->rsc;
    }
    if (rh_rsc == NULL && rh_action) {
        rh_rsc = rh_action->rsc;
    }

    if ((lh_action == NULL && lh_rsc == NULL)
        || (rh_action == NULL && rh_rsc == NULL)) {
        crm_config_err("Invalid inputs %p.%p %p.%p", lh_rsc, lh_action, rh_rsc, rh_action);
        free(lh_action_task);
        free(rh_action_task);
        return -1;
    }

    order = calloc(1, sizeof(order_constraint_t));

    order->id = data_set->order_id++;
    order->type = type;
    order->lh_rsc = lh_rsc;
    order->rh_rsc = rh_rsc;
    order->lh_action = lh_action;
    order->rh_action = rh_action;
    order->lh_action_task = lh_action_task;
    order->rh_action_task = rh_action_task;

    if (order->lh_action_task == NULL && lh_action) {
        order->lh_action_task = crm_strdup(lh_action->uuid);
    }

    if (order->rh_action_task == NULL && rh_action) {
        order->rh_action_task = crm_strdup(rh_action->uuid);
    }

    if (order->lh_rsc == NULL && lh_action) {
        order->lh_rsc = lh_action->rsc;
    }

    if (order->rh_rsc == NULL && rh_action) {
        order->rh_rsc = rh_action->rsc;
    }

    data_set->ordering_constraints = g_list_prepend(data_set->ordering_constraints, order);

    return order->id;
}

enum pe_ordering
get_asymmetrical_flags(enum pe_order_kind kind)
{
    enum pe_ordering flags = pe_order_optional;

    if (kind == pe_order_kind_mandatory) {
        flags |= pe_order_asymmetrical;
    } else if (kind == pe_order_kind_serialize) {
        flags |= pe_order_serialize_only;
    }
    return flags;
}

enum pe_ordering
get_flags(const char *id, enum pe_order_kind kind,
          const char *action_first, const char *action_then, gboolean invert)
{
    enum pe_ordering flags = pe_order_optional;

    if (invert && kind == pe_order_kind_mandatory) {
        crm_trace("Upgrade %s: implies left", id);
        flags |= pe_order_implies_first;

    } else if (kind == pe_order_kind_mandatory) {
        crm_trace("Upgrade %s: implies right", id);
        flags |= pe_order_implies_then;
        if (safe_str_eq(action_first, RSC_START)
            || safe_str_eq(action_first, RSC_PROMOTE)) {
            crm_trace("Upgrade %s: runnable", id);
            flags |= pe_order_runnable_left;
        }

    } else if (kind == pe_order_kind_serialize) {
        flags |= pe_order_serialize_only;
    }

    return flags;
}

static gboolean
unpack_order_set(xmlNode * set, enum pe_order_kind kind, resource_t ** rsc,
                 action_t ** begin, action_t ** end, action_t ** inv_begin, action_t ** inv_end,
                 const char *symmetrical, pe_working_set_t * data_set)
{
    xmlNode *xml_rsc = NULL;
    GListPtr set_iter = NULL;
    GListPtr resources = NULL;

    resource_t *last = NULL;
    resource_t *resource = NULL;

    int local_kind = kind;
    gboolean sequential = FALSE;
    enum pe_ordering flags = pe_order_optional;

    char *key = NULL;
    const char *id = ID(set);
    const char *action = crm_element_value(set, "action");
    const char *sequential_s = crm_element_value(set, "sequential");
    const char *kind_s = crm_element_value(set, XML_ORDER_ATTR_KIND);

    /*
       char *pseudo_id = NULL;
       char *end_id    = NULL;
       char *begin_id  = NULL;
     */

    if (action == NULL) {
        action = RSC_START;
    }

    if (kind_s) {
        local_kind = get_ordering_type(set);
    }
    if (sequential_s == NULL) {
        sequential_s = "1";
    }

    sequential = crm_is_true(sequential_s);
    if (crm_is_true(symmetrical)) {
        flags = get_flags(id, local_kind, action, action, FALSE);
    } else {
        flags = get_asymmetrical_flags(local_kind);
    }

    for (xml_rsc = __xml_first_child(set); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
        if (crm_str_eq((const char *)xml_rsc->name, XML_TAG_RESOURCE_REF, TRUE)) {
            EXPAND_CONSTRAINT_IDREF(id, resource, ID(xml_rsc));
            resources = g_list_append(resources, resource);
        }
    }

    if (g_list_length(resources) == 1) {
        crm_trace("Single set: %s", id);
        *rsc = resource;
        *end = NULL;
        *begin = NULL;
        *inv_end = NULL;
        *inv_begin = NULL;
        goto done;
    }

    /*
       pseudo_id = crm_concat(id, action, '-');
       end_id    = crm_concat(pseudo_id, "end", '-');
       begin_id  = crm_concat(pseudo_id, "begin", '-');
     */

    *rsc = NULL;
    /*
     *end = get_pseudo_op(end_id, data_set);
     *begin = get_pseudo_op(begin_id, data_set);    

     free(pseudo_id);
     free(begin_id);
     free(end_id);
     */

    set_iter = resources;
    while (set_iter != NULL) {
        resource = (resource_t *) set_iter->data;
        set_iter = set_iter->next;

        key = generate_op_key(resource->id, action, 0);

        /*
           custom_action_order(NULL, NULL, *begin, resource, crm_strdup(key), NULL,
           flags|pe_order_implies_first_printed, data_set);

           custom_action_order(resource, crm_strdup(key), NULL, NULL, NULL, *end,
           flags|pe_order_implies_then_printed, data_set);
         */

        if (local_kind == pe_order_kind_serialize) {
            /* Serialize before everything that comes after */

            GListPtr gIter = NULL;

            for (gIter = set_iter; gIter != NULL; gIter = gIter->next) {
                resource_t *then_rsc = (resource_t *) gIter->data;
                char *then_key = generate_op_key(then_rsc->id, action, 0);

                custom_action_order(resource, crm_strdup(key), NULL, then_rsc, then_key, NULL,
                                    flags, data_set);
            }

        } else if (sequential) {
            if (last != NULL) {
                new_rsc_order(last, action, resource, action, flags, data_set);
            }
            last = resource;
        }
        free(key);
    }

    if (crm_is_true(symmetrical) == FALSE) {
        goto done;

    } else if (symmetrical && local_kind == pe_order_kind_serialize) {
        crm_config_warn("Cannot invert serialized constraint set %s", id);
        goto done;

    } else if (local_kind == pe_order_kind_serialize) {
        goto done;
    }

    last = NULL;
    action = invert_action(action);

    /*
       pseudo_id = crm_concat(id, action, '-');
       end_id    = crm_concat(pseudo_id, "end", '-');
       begin_id  = crm_concat(pseudo_id, "begin", '-');

       *inv_end = get_pseudo_op(end_id, data_set);
       *inv_begin = get_pseudo_op(begin_id, data_set);

       free(pseudo_id);
       free(begin_id);
       free(end_id);
     */

    flags = get_flags(id, local_kind, action, action, TRUE);

    set_iter = resources;
    while (set_iter != NULL) {
        resource = (resource_t *) set_iter->data;
        set_iter = set_iter->next;

        /*
           key = generate_op_key(resource->id, action, 0);

           custom_action_order(NULL, NULL, *inv_begin, resource, crm_strdup(key), NULL,
           flags|pe_order_implies_first_printed, data_set);

           custom_action_order(resource, key, NULL, NULL, NULL, *inv_end,
           flags|pe_order_implies_then_printed, data_set);
         */

        if (sequential) {
            if (last != NULL) {
                new_rsc_order(resource, action, last, action, flags, data_set);
            }
            last = resource;
        }
    }

  done:
    g_list_free(resources);
    return TRUE;
}

static gboolean
order_rsc_sets(const char *id, xmlNode * set1, xmlNode * set2, enum pe_order_kind kind,
               pe_working_set_t * data_set, gboolean invert, gboolean symmetrical)
{

    xmlNode *xml_rsc = NULL;

    resource_t *rsc_1 = NULL;
    resource_t *rsc_2 = NULL;

    const char *action_1 = crm_element_value(set1, "action");
    const char *action_2 = crm_element_value(set2, "action");

    const char *sequential_1 = crm_element_value(set1, "sequential");
    const char *sequential_2 = crm_element_value(set2, "sequential");

    const char *require_all_s = crm_element_value(set1, "require-all");
    gboolean require_all = require_all_s ? crm_is_true(require_all_s) : TRUE;

    enum pe_ordering flags = pe_order_none;

    if (action_1 == NULL) {
        action_1 = RSC_START;
    };

    if (action_2 == NULL) {
        action_2 = RSC_START;
    };

    if (invert) {
        action_1 = invert_action(action_1);
        action_2 = invert_action(action_2);
    }

    if (symmetrical == FALSE) {
        flags = get_asymmetrical_flags(kind);
    } else {
        flags = get_flags(id, kind, action_2, action_1, invert);
    }

    /* If we have an un-ordered set1, whether it is sequential or not is irrelevant in regards to set2. */
    if (!require_all) {
        char *task = crm_concat(CRM_OP_RELAXED_SET, ID(set1), ':');
        action_t *unordered_action = get_pseudo_op(task, data_set);

        free(task);
        update_action_flags(unordered_action, pe_action_requires_any);

        for (xml_rsc = __xml_first_child(set1); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
            xmlNode *xml_rsc_2 = NULL;
            if (!crm_str_eq((const char *)xml_rsc->name, XML_TAG_RESOURCE_REF, TRUE)) {
                continue;
            }

            EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));

            /* Add an ordering constraint between every element in set1 and the pseudo action.
             * If any action in set1 is runnable the pseudo action will be runnable. */
            custom_action_order(rsc_1, generate_op_key(rsc_1->id, action_1, 0), NULL,
                                NULL,NULL, unordered_action,
                                pe_order_one_or_more|pe_order_implies_then_printed, data_set);

            for (xml_rsc_2 = __xml_first_child(set2); xml_rsc_2 != NULL; xml_rsc_2 = __xml_next(xml_rsc_2)) {
                if (!crm_str_eq((const char *)xml_rsc_2->name, XML_TAG_RESOURCE_REF, TRUE)) {
                    continue;
                }

                EXPAND_CONSTRAINT_IDREF(id, rsc_2, ID(xml_rsc_2));

                /* Add an ordering constraint between the pseudo action and every element in set2.
                 * If the pseudo action is runnable, every action in set2 will be runnable */
                custom_action_order(NULL, NULL, unordered_action,
                    rsc_2, generate_op_key(rsc_2->id, action_2, 0), NULL,
                    flags|pe_order_runnable_left, data_set);
            }
        }

        return TRUE;
    }

    if (crm_is_true(sequential_1)) {
        if (invert == FALSE) {
            /* get the last one */
            const char *rid = NULL;

            for (xml_rsc = __xml_first_child(set1); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
                if (crm_str_eq((const char *)xml_rsc->name, XML_TAG_RESOURCE_REF, TRUE)) {
                    rid = ID(xml_rsc);
                }
            }
            EXPAND_CONSTRAINT_IDREF(id, rsc_1, rid);

        } else {
            /* get the first one */
            for (xml_rsc = __xml_first_child(set1); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
                if (crm_str_eq((const char *)xml_rsc->name, XML_TAG_RESOURCE_REF, TRUE)) {
                    EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));
                    break;
                }
            }
        }
    }

    if (crm_is_true(sequential_2)) {
        if (invert == FALSE) {
            /* get the first one */
            for (xml_rsc = __xml_first_child(set2); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
                if (crm_str_eq((const char *)xml_rsc->name, XML_TAG_RESOURCE_REF, TRUE)) {
                    EXPAND_CONSTRAINT_IDREF(id, rsc_2, ID(xml_rsc));
                    break;
                }
            }

        } else {
            /* get the last one */
            const char *rid = NULL;

            for (xml_rsc = __xml_first_child(set2); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
                if (crm_str_eq((const char *)xml_rsc->name, XML_TAG_RESOURCE_REF, TRUE)) {
                    rid = ID(xml_rsc);
                }
            }
            EXPAND_CONSTRAINT_IDREF(id, rsc_2, rid);
        }
    }

    if (rsc_1 != NULL && rsc_2 != NULL) {
        new_rsc_order(rsc_1, action_1, rsc_2, action_2, flags, data_set);

    } else if (rsc_1 != NULL) {
        for (xml_rsc = __xml_first_child(set2); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
            if (crm_str_eq((const char *)xml_rsc->name, XML_TAG_RESOURCE_REF, TRUE)) {
                EXPAND_CONSTRAINT_IDREF(id, rsc_2, ID(xml_rsc));
                new_rsc_order(rsc_1, action_1, rsc_2, action_2, flags, data_set);
            }
        }

    } else if (rsc_2 != NULL) {
        xmlNode *xml_rsc = NULL;

        for (xml_rsc = __xml_first_child(set1); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
            if (crm_str_eq((const char *)xml_rsc->name, XML_TAG_RESOURCE_REF, TRUE)) {
                EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));
                new_rsc_order(rsc_1, action_1, rsc_2, action_2, flags, data_set);
            }
        }

    } else {
        for (xml_rsc = __xml_first_child(set1); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
            if (crm_str_eq((const char *)xml_rsc->name, XML_TAG_RESOURCE_REF, TRUE)) {
                xmlNode *xml_rsc_2 = NULL;

                EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));

                for (xml_rsc_2 = __xml_first_child(set2); xml_rsc_2 != NULL;
                     xml_rsc_2 = __xml_next(xml_rsc_2)) {
                    if (crm_str_eq((const char *)xml_rsc_2->name, XML_TAG_RESOURCE_REF, TRUE)) {
                        EXPAND_CONSTRAINT_IDREF(id, rsc_2, ID(xml_rsc_2));
                        new_rsc_order(rsc_1, action_1, rsc_2, action_2, flags, data_set);
                    }
                }
            }
        }
    }

    return TRUE;
}

static gboolean
expand_templates_in_sets(xmlNode *xml_obj, xmlNode **expanded_xml, pe_working_set_t *data_set)
{
    xmlNode *new_xml = NULL;
    xmlNode *set = NULL;
    gboolean any_refs = FALSE;

    *expanded_xml = NULL;

    if(xml_obj == NULL) {
	crm_config_err("No constraint object to process.");
	return FALSE;
    }

    new_xml = copy_xml(xml_obj);

    for (set = __xml_first_child(new_xml); set != NULL; set = __xml_next(set)) {
        xmlNode *xml_rsc = NULL;
        GListPtr template_refs = NULL;
        GListPtr gIter = NULL;

        if (safe_str_neq((const char *)set->name, XML_CONS_TAG_RSC_SET)) {
            continue;
        }

        for (xml_rsc = __xml_first_child(set); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
            xmlNode *template_rsc_set = NULL;

            if (safe_str_neq((const char *)xml_rsc->name, XML_TAG_RESOURCE_REF)) {
                continue;
            }

            template_rsc_set = g_hash_table_lookup(data_set->template_rsc_sets, ID(xml_rsc));
            if (template_rsc_set) {
                /* The resource_ref under the resource_set references a template */
                xmlNode *rsc_ref = NULL;
                xmlNode *new_rsc_ref = NULL;
                xmlNode *last_ref = xml_rsc;

                /* A sample: 

                   Original XML:
                 
                   <resource_set id="template1-order-0" sequential="true">
                     <resource_ref id="rsc1"/>
                     <resource_ref id="template1"/>
                     <resource_ref id="rsc4"/>
                   </resource_set>

                   Now we are appending rsc2 and rsc3 which are derived from template1 right after it:

                   <resource_set id="template1-order-0" sequential="true">
                     <resource_ref id="rsc1"/>
                     <resource_ref id="template1"/>
                     <resource_ref id="rsc2"/>
                     <resource_ref id="rsc3"/>
                     <resource_ref id="rsc4"/>
                   </resource_set>

                 */
                for (rsc_ref = __xml_first_child(template_rsc_set); rsc_ref != NULL; rsc_ref = __xml_next(rsc_ref)) {
                    new_rsc_ref = xmlDocCopyNode(rsc_ref, getDocPtr(set), 1);
                    xmlAddNextSibling(last_ref, new_rsc_ref);

                    last_ref = new_rsc_ref;
                }

                any_refs = TRUE;

                /* Do not directly free '<resource_ref id="template1"/>'.
                   That would break the further __xml_next(xml_rsc)) and cause "Invalid read" seen by valgrind.
                   So just record it into a hash table for freeing it later.
                 */
                template_refs = g_list_append(template_refs, xml_rsc);
            }
        }

        /* Now free '<resource_ref id="template1"/>', and finally get:

           <resource_set id="template1-order-0" sequential="true">
             <resource_ref id="rsc1"/>
             <resource_ref id="rsc2"/>
             <resource_ref id="rsc3"/>
             <resource_ref id="rsc4"/>
           </resource_set>

         */
        for (gIter = template_refs; gIter != NULL; gIter = gIter->next) {
            xmlNode *template_ref = gIter->data;
            free_xml_from_parent(NULL, template_ref);
        }
        g_list_free(template_refs);
    }

    if (any_refs) {
        *expanded_xml = new_xml;
    } else {
	free_xml(new_xml);
    }

    return TRUE;
}

static gboolean
template_to_set(xmlNode *xml_obj, xmlNode **rsc_set, const char *attr,
		gboolean convert_rsc, pe_working_set_t *data_set)
{
    const char *cons_id = NULL;
    const char *id = NULL;

    resource_t *rsc = NULL;
    
    *rsc_set = NULL;

    if(xml_obj == NULL) {
	crm_config_err("No constraint object to process.");
	return FALSE;
    }

    if(attr == NULL) {
	crm_config_err("No attribute name to process.");
	return FALSE;
    }
    
    cons_id = crm_element_value(xml_obj, XML_ATTR_ID);
    if(cons_id == NULL) {
	crm_config_err("%s constraint must have an id", crm_element_name(xml_obj));
	return FALSE;
    }

    id = crm_element_value(xml_obj, attr);
    if(id == NULL) {
	return TRUE;
    }

    rsc = pe_find_resource(data_set->resources, id);
    if(rsc == NULL) {
	xmlNode *template_rsc_set = g_hash_table_lookup(data_set->template_rsc_sets, id);

	if(template_rsc_set == NULL) {
	    crm_config_err("Invalid constraint '%s': No template named '%s'", cons_id, id);
	    return FALSE;
	}

        /* A template is referenced by the "attr" attribute (first, then, rsc or with-rsc).
           Add the template's corresponding "resource_set" which contains the primitives derived
           from it under the constraint. */
	*rsc_set = add_node_copy(xml_obj, template_rsc_set);

        /* Set sequential="false" for the resource_set */
	crm_xml_add(*rsc_set, "sequential", XML_BOOLEAN_FALSE);

    } else if(convert_rsc) {
        /* Even a regular resource is referenced by "attr", convert it into a resource_set.
           Because the other side of the constraint could be a template reference. */
	xmlNode *rsc_ref = NULL;

	*rsc_set = create_xml_node(xml_obj, XML_CONS_TAG_RSC_SET);
	crm_xml_add(*rsc_set, XML_ATTR_ID, id);

	rsc_ref = create_xml_node(*rsc_set, XML_TAG_RESOURCE_REF);
	crm_xml_add(rsc_ref, XML_ATTR_ID, id);

    } else {
	return TRUE;
    }

    /* Remove the "attr" attribute referencing the template */
    if(*rsc_set) {
	xml_remove_prop(xml_obj, attr);
    }

    return TRUE;
}

static gboolean
unpack_order_template(xmlNode *xml_obj, xmlNode **expanded_xml, pe_working_set_t *data_set)
{
    const char *id = NULL;
    const char *id_first  = NULL;
    const char *id_then  = NULL;
    const char *action_first = NULL;
    const char *action_then = NULL;

    resource_t *rsc_first = NULL;
    resource_t *rsc_then = NULL;

    xmlNode *new_xml = NULL;
    xmlNode *rsc_set_first = NULL;
    xmlNode *rsc_set_then = NULL;
    gboolean any_sets = FALSE;

    *expanded_xml = NULL;

    if(xml_obj == NULL) {
	crm_config_err("No constraint object to process.");
	return FALSE;
    }

    id = crm_element_value(xml_obj, XML_ATTR_ID);
    if(id == NULL) {
	crm_config_err("%s constraint must have an id", crm_element_name(xml_obj));
	return FALSE;
    }

    /* Attempt to expand any template references in possible resource sets. */
    expand_templates_in_sets(xml_obj, &new_xml, data_set);
    if (new_xml) {
        /* There are resource sets referencing templates. Return with the expanded XML. */
	crm_log_xml_trace(new_xml, "Expanded rsc_order...");
	*expanded_xml = new_xml;
	return TRUE;
    }

    id_first = crm_element_value(xml_obj, XML_ORDER_ATTR_FIRST);
    id_then  = crm_element_value(xml_obj, XML_ORDER_ATTR_THEN);
    if(id_first == NULL || id_then == NULL) {
	return TRUE;
    }

    rsc_first = pe_find_resource(data_set->resources, id_first);
    rsc_then = pe_find_resource(data_set->resources, id_then);
    if(rsc_first && rsc_then) {
        /* Neither side references any template. */
	return TRUE;
    }

    if (rsc_first == NULL) {
        xmlNode *template_rsc_set_first = NULL;
        gboolean rc = g_hash_table_lookup_extended(data_set->template_rsc_sets, id_first,
                                                   NULL, (gpointer) &template_rsc_set_first);

        if (rc == FALSE) {
            crm_config_err("Invalid constraint '%s': No resource or template named '%s'", id, id_first);
            return FALSE;

        } else if (template_rsc_set_first == NULL) {
            crm_config_warn("Constraint '%s': No resource is derived from template '%s'", id, id_first);
            return FALSE;
        }
    }

    if (rsc_then == NULL) {
        xmlNode *template_rsc_set_then = NULL;
        gboolean rc = g_hash_table_lookup_extended(data_set->template_rsc_sets, id_then,
                                                   NULL, (gpointer) &template_rsc_set_then);

        if (rc == FALSE) {
            crm_config_err("Invalid constraint '%s': No resource or template named '%s'", id, id_then);
            return FALSE;

        } else if (template_rsc_set_then == NULL) {
            crm_config_warn("Constraint '%s': No resource is derived from template '%s'", id, id_then);
            return FALSE;
        }
    }

    action_first = crm_element_value(xml_obj, XML_ORDER_ATTR_FIRST_ACTION);
    action_then  = crm_element_value(xml_obj, XML_ORDER_ATTR_THEN_ACTION);

    new_xml = copy_xml(xml_obj);

    /* Convert the template reference in "first" into a resource_set under the order constraint. */
    if(template_to_set(new_xml, &rsc_set_first, XML_ORDER_ATTR_FIRST,
			    TRUE, data_set) == FALSE) {
	free_xml(new_xml);
	return FALSE;
    }

    if(rsc_set_first) {
	if(action_first) {
            /* A "first-action" is specified.
               Move it into the converted resource_set as an "action" attribute. */
	    crm_xml_add(rsc_set_first, "action", action_first);
	    xml_remove_prop(new_xml, XML_ORDER_ATTR_FIRST_ACTION);
	}
	any_sets = TRUE;
    }

    /* Convert the template reference in "then" into a resource_set under the order constraint. */
    if(template_to_set(new_xml, &rsc_set_then, XML_ORDER_ATTR_THEN,
			    TRUE, data_set) == FALSE) {
	free_xml(new_xml);
	return FALSE;
    }

    if(rsc_set_then) {
	if(action_then) {
            /* A "then-action" is specified.
               Move it into the converted resource_set as an "action" attribute. */
	    crm_xml_add(rsc_set_then, "action", action_then);
	    xml_remove_prop(new_xml, XML_ORDER_ATTR_THEN_ACTION);
	}
	any_sets = TRUE;
    }

    if(any_sets) {
	crm_log_xml_trace(new_xml, "Expanded rsc_order...");
	*expanded_xml = new_xml;
    } else {
	free_xml(new_xml);
    }

    return TRUE;
}

gboolean
unpack_rsc_order(xmlNode * xml_obj, pe_working_set_t * data_set)
{
    gboolean any_sets = FALSE;

    resource_t *rsc = NULL;

    /*
       resource_t *last_rsc = NULL;
     */

    action_t *set_end = NULL;
    action_t *set_begin = NULL;

    action_t *set_inv_end = NULL;
    action_t *set_inv_begin = NULL;

    xmlNode *set = NULL;
    xmlNode *last = NULL;

    xmlNode *orig_xml = NULL;
    xmlNode *expanded_xml = NULL;

    /*
       action_t *last_end = NULL;
       action_t *last_begin = NULL;
       action_t *last_inv_end = NULL;
       action_t *last_inv_begin = NULL;
     */

    const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
    const char *invert = crm_element_value(xml_obj, XML_CONS_ATTR_SYMMETRICAL);
    enum pe_order_kind kind = get_ordering_type(xml_obj);

    gboolean invert_bool = TRUE;
    gboolean rc = TRUE;

    if (invert == NULL) {
        invert = "true";
    }

    invert_bool = crm_is_true(invert);

    rc = unpack_order_template(xml_obj, &expanded_xml, data_set);
    if(expanded_xml) {
	orig_xml = xml_obj;
	xml_obj = expanded_xml;

    } else if (rc == FALSE) {
        return FALSE;
    }

    for (set = __xml_first_child(xml_obj); set != NULL; set = __xml_next(set)) {
        if (crm_str_eq((const char *)set->name, XML_CONS_TAG_RSC_SET, TRUE)) {
            any_sets = TRUE;
            set = expand_idref(set, data_set->input);
            if (unpack_order_set(set, kind, &rsc, &set_begin, &set_end,
                                 &set_inv_begin, &set_inv_end, invert, data_set) == FALSE) {
                return FALSE;

                /* Expand orders in order_rsc_sets() instead of via pseudo actions. */
                /*
                   } else if(last) {
                   const char *set_action = crm_element_value(set, "action");
                   const char *last_action = crm_element_value(last, "action");
                   enum pe_ordering flags = get_flags(id, kind, last_action, set_action, FALSE);

                   if(!set_action) { set_action = RSC_START; }
                   if(!last_action) { last_action = RSC_START; }

                   if(rsc == NULL && last_rsc == NULL) {
                   order_actions(last_end, set_begin, flags);
                   } else {
                   custom_action_order(
                   last_rsc, null_or_opkey(last_rsc, last_action), last_end,
                   rsc, null_or_opkey(rsc, set_action), set_begin,
                   flags, data_set);
                   }

                   if(crm_is_true(invert)) {
                   set_action = invert_action(set_action);
                   last_action = invert_action(last_action);

                   flags = get_flags(id, kind, last_action, set_action, TRUE);
                   if(rsc == NULL && last_rsc == NULL) {
                   order_actions(last_inv_begin, set_inv_end, flags);

                   } else {
                   custom_action_order(
                   last_rsc, null_or_opkey(last_rsc, last_action), last_inv_begin,
                   rsc, null_or_opkey(rsc, set_action), set_inv_end,
                   flags, data_set);
                   }
                   }
                 */

            } else if ( /* never called -- Now call it for supporting clones in resource sets */
                       last) {
                if (order_rsc_sets(id, last, set, kind, data_set, FALSE, invert_bool) == FALSE) {
                    return FALSE;
                }

                if (invert_bool && order_rsc_sets(id, set, last, kind, data_set, TRUE, invert_bool) == FALSE) {
                    return FALSE;
                }

            }
            last = set;
            /*
               last_rsc = rsc;
               last_end = set_end;
               last_begin = set_begin;
               last_inv_end = set_inv_end;
               last_inv_begin = set_inv_begin;
             */
        }
    }

    if(expanded_xml) {
	free_xml(expanded_xml);
	xml_obj = orig_xml;
    }

    if (any_sets == FALSE) {
        return unpack_simple_rsc_order(xml_obj, data_set);
    }

    return TRUE;
}

static gboolean
unpack_colocation_set(xmlNode * set, int score, pe_working_set_t * data_set)
{
    xmlNode *xml_rsc = NULL;
    resource_t *with = NULL;
    resource_t *resource = NULL;
    const char *set_id = ID(set);
    const char *role = crm_element_value(set, "role");
    const char *sequential = crm_element_value(set, "sequential");
    int local_score = score;

    const char *score_s = crm_element_value(set, XML_RULE_ATTR_SCORE);

    if (score_s) {
        local_score = char2score(score_s);
    }

    if (sequential != NULL && crm_is_true(sequential) == FALSE) {
        return TRUE;

    } else if (local_score >= 0) {
        for (xml_rsc = __xml_first_child(set); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
            if (crm_str_eq((const char *)xml_rsc->name, XML_TAG_RESOURCE_REF, TRUE)) {
                EXPAND_CONSTRAINT_IDREF(set_id, resource, ID(xml_rsc));
                if (with != NULL) {
                    crm_trace("Colocating %s with %s", resource->id, with->id);
                    rsc_colocation_new(set_id, NULL, local_score, resource, with, role, role,
                                       data_set);
                }

                with = resource;
            }
        }

    } else {
        /* Anti-colocating with every prior resource is
         * the only way to ensure the intuitive result
         * (ie. that no-one in the set can run with anyone
         * else in the set)
         */

        for (xml_rsc = __xml_first_child(set); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
            if (crm_str_eq((const char *)xml_rsc->name, XML_TAG_RESOURCE_REF, TRUE)) {
                xmlNode *xml_rsc_with = NULL;

                EXPAND_CONSTRAINT_IDREF(set_id, resource, ID(xml_rsc));

                for (xml_rsc_with = __xml_first_child(set); xml_rsc_with != NULL;
                     xml_rsc_with = __xml_next(xml_rsc_with)) {
                    if (crm_str_eq((const char *)xml_rsc_with->name, XML_TAG_RESOURCE_REF, TRUE)) {
                        if (safe_str_eq(resource->id, ID(xml_rsc_with))) {
                            break;
                        } else if (resource == NULL) {
                            crm_config_err("%s: No resource found for %s", set_id,
                                           ID(xml_rsc_with));
                            return FALSE;
                        }
                        EXPAND_CONSTRAINT_IDREF(set_id, with, ID(xml_rsc_with));
                        crm_trace("Anti-Colocating %s with %s", resource->id, with->id);
                        rsc_colocation_new(set_id, NULL, local_score, resource, with, role, role,
                                           data_set);
                    }
                }
            }
        }
    }

    return TRUE;
}

static gboolean
colocate_rsc_sets(const char *id, xmlNode * set1, xmlNode * set2, int score,
                  pe_working_set_t * data_set)
{
    xmlNode *xml_rsc = NULL;
    resource_t *rsc_1 = NULL;
    resource_t *rsc_2 = NULL;

    const char *role_1 = crm_element_value(set1, "role");
    const char *role_2 = crm_element_value(set2, "role");

    const char *sequential_1 = crm_element_value(set1, "sequential");
    const char *sequential_2 = crm_element_value(set2, "sequential");

    if (crm_is_true(sequential_1)) {
        /* get the first one */
        for (xml_rsc = __xml_first_child(set1); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
            if (crm_str_eq((const char *)xml_rsc->name, XML_TAG_RESOURCE_REF, TRUE)) {
                EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));
                break;
            }
        }
    }

    if (crm_is_true(sequential_2)) {
        /* get the last one */
        const char *rid = NULL;

        for (xml_rsc = __xml_first_child(set2); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
            if (crm_str_eq((const char *)xml_rsc->name, XML_TAG_RESOURCE_REF, TRUE)) {
                rid = ID(xml_rsc);
            }
        }
        EXPAND_CONSTRAINT_IDREF(id, rsc_2, rid);
    }

    if (rsc_1 != NULL && rsc_2 != NULL) {
        rsc_colocation_new(id, NULL, score, rsc_1, rsc_2, role_1, role_2, data_set);

    } else if (rsc_1 != NULL) {
        for (xml_rsc = __xml_first_child(set2); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
            if (crm_str_eq((const char *)xml_rsc->name, XML_TAG_RESOURCE_REF, TRUE)) {
                EXPAND_CONSTRAINT_IDREF(id, rsc_2, ID(xml_rsc));
                rsc_colocation_new(id, NULL, score, rsc_1, rsc_2, role_1, role_2, data_set);
            }
        }

    } else if (rsc_2 != NULL) {
        for (xml_rsc = __xml_first_child(set1); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
            if (crm_str_eq((const char *)xml_rsc->name, XML_TAG_RESOURCE_REF, TRUE)) {
                EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));
                rsc_colocation_new(id, NULL, score, rsc_1, rsc_2, role_1, role_2, data_set);
            }
        }

    } else {
        for (xml_rsc = __xml_first_child(set1); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
            if (crm_str_eq((const char *)xml_rsc->name, XML_TAG_RESOURCE_REF, TRUE)) {
                xmlNode *xml_rsc_2 = NULL;

                EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));

                for (xml_rsc_2 = __xml_first_child(set2); xml_rsc_2 != NULL;
                     xml_rsc_2 = __xml_next(xml_rsc_2)) {
                    if (crm_str_eq((const char *)xml_rsc_2->name, XML_TAG_RESOURCE_REF, TRUE)) {
                        EXPAND_CONSTRAINT_IDREF(id, rsc_2, ID(xml_rsc_2));
                        rsc_colocation_new(id, NULL, score, rsc_1, rsc_2, role_1, role_2, data_set);
                    }
                }
            }
        }
    }

    return TRUE;
}

static gboolean
unpack_simple_colocation(xmlNode * xml_obj, pe_working_set_t * data_set)
{
    int score_i = 0;

    const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
    const char *score = crm_element_value(xml_obj, XML_RULE_ATTR_SCORE);

    const char *id_lh = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE);
    const char *id_rh = crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET);
    const char *state_lh = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE_ROLE);
    const char *state_rh = crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET_ROLE);
    const char *instance_lh = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE_INSTANCE);
    const char *instance_rh = crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET_INSTANCE);
    const char *attr = crm_element_value(xml_obj, XML_COLOC_ATTR_NODE_ATTR);

    const char *symmetrical = crm_element_value(xml_obj, XML_CONS_ATTR_SYMMETRICAL);

    resource_t *rsc_lh = pe_find_resource(data_set->resources, id_lh);
    resource_t *rsc_rh = pe_find_resource(data_set->resources, id_rh);

    if (rsc_lh == NULL) {
        crm_config_err("Invalid constraint '%s': No resource named '%s'", id, id_lh);
        return FALSE;

    } else if (rsc_rh == NULL) {
        crm_config_err("Invalid constraint '%s': No resource named '%s'", id, id_rh);
        return FALSE;

    } else if (instance_lh && rsc_lh->variant < pe_clone) {
        crm_config_err
            ("Invalid constraint '%s': Resource '%s' is not a clone but instance %s was requested",
             id, id_lh, instance_lh);
        return FALSE;

    } else if (instance_rh && rsc_rh->variant < pe_clone) {
        crm_config_err
            ("Invalid constraint '%s': Resource '%s' is not a clone but instance %s was requested",
             id, id_rh, instance_rh);
        return FALSE;
    }

    if (instance_lh) {
        rsc_lh = find_clone_instance(rsc_lh, instance_lh, data_set);
        if (rsc_lh == NULL) {
            crm_config_warn("Invalid constraint '%s': No instance '%s' of '%s'", id, instance_lh,
                            id_lh);
            return FALSE;
        }
    }

    if (instance_rh) {
        rsc_rh = find_clone_instance(rsc_rh, instance_rh, data_set);
        if (rsc_rh == NULL) {
            crm_config_warn("Invalid constraint '%s': No instance '%s' of '%s'", id, instance_rh,
                            id_rh);
            return FALSE;
        }
    }

    if (crm_is_true(symmetrical)) {
        crm_config_warn("The %s colocation constraint attribute has been removed."
                        "  It didn't do what you think it did anyway.", XML_CONS_ATTR_SYMMETRICAL);
    }

    if (score) {
        score_i = char2score(score);
    }

    rsc_colocation_new(id, attr, score_i, rsc_lh, rsc_rh, state_lh, state_rh, data_set);
    return TRUE;
}

static gboolean
unpack_colocation_template(xmlNode *xml_obj, xmlNode **expanded_xml, pe_working_set_t *data_set)
{
    const char *id = NULL;
    const char *id_lh = NULL;
    const char *id_rh = NULL;
    const char *state_lh = NULL;
    const char *state_rh = NULL;

    resource_t *rsc_lh = NULL;
    resource_t *rsc_rh = NULL;

    xmlNode *template_rsc_set_lh = NULL;
    xmlNode *template_rsc_set_rh = NULL;

    xmlNode *new_xml = NULL;
    xmlNode *rsc_set_lh = NULL;
    xmlNode *rsc_set_rh = NULL;
    gboolean any_sets = FALSE;

    *expanded_xml = NULL;

    if(xml_obj == NULL) {
	crm_config_err("No constraint object to process.");
	return FALSE;
    }

    id = crm_element_value(xml_obj, XML_ATTR_ID);
    if(id == NULL) {
	crm_config_err("%s constraint must have an id", crm_element_name(xml_obj));
	return FALSE;
    }

    /* Attempt to expand any template references in possible resource sets. */
    expand_templates_in_sets(xml_obj, &new_xml, data_set);
    if (new_xml) {
        /* There are resource sets referencing templates. Return with the expanded XML. */
	crm_log_xml_trace(new_xml, "Expanded rsc_colocation...");
	*expanded_xml = new_xml;
	return TRUE;
    }

    id_lh = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE);
    id_rh = crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET);
    if(id_lh == NULL || id_rh == NULL) {
	return TRUE;
    }

    rsc_lh = pe_find_resource(data_set->resources, id_lh);
    rsc_rh = pe_find_resource(data_set->resources, id_rh);
    if(rsc_lh && rsc_rh) {
        /* Neither side references any template. */
	return TRUE;
    }

    if (rsc_lh == NULL) {
        gboolean rc = g_hash_table_lookup_extended(data_set->template_rsc_sets, id_lh,
                                                   NULL, (gpointer) &template_rsc_set_lh);

        if (rc == FALSE) {
            crm_config_err("Invalid constraint '%s': No resource or template named '%s'", id, id_lh);
            return FALSE;

        } else if (template_rsc_set_lh == NULL) {
            crm_config_warn("Constraint '%s': No resource is derived from template '%s'", id, id_lh);
            return FALSE;
        }
    }

    if (rsc_rh == NULL) {
        gboolean rc = g_hash_table_lookup_extended(data_set->template_rsc_sets, id_rh,
                                                   NULL, (gpointer) &template_rsc_set_rh);

        if (rc == FALSE) {
            crm_config_err("Invalid constraint '%s': No resource or template named '%s'", id, id_rh);
            return FALSE;

        } else if (template_rsc_set_rh == NULL) {
            crm_config_warn("Constraint '%s': No resource is derived from template '%s'", id, id_rh);
            return FALSE;
        }
    }

    if(template_rsc_set_lh && template_rsc_set_rh) {
        /* A colocation constraint between two templates makes no sense. */
	crm_config_err("Either LHS or RHS of %s should be a normal resource instead of a template",  id);
	return FALSE;
    }

    state_lh = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE_ROLE);
    state_rh = crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET_ROLE);

    new_xml = copy_xml(xml_obj);

    /* Convert the template reference in "rsc" into a resource_set under the colocation constraint. */
    if(template_to_set(new_xml, &rsc_set_lh, XML_COLOC_ATTR_SOURCE,
			    TRUE, data_set) == FALSE) {
	free_xml(new_xml);
	return FALSE;
    }

    if(rsc_set_lh) {
	if(state_lh) {
            /* A "rsc-role" is specified.
               Move it into the converted resource_set as a "role"" attribute. */
	    crm_xml_add(rsc_set_lh, "role", state_lh);
	    xml_remove_prop(new_xml, XML_COLOC_ATTR_SOURCE_ROLE);
	}
	any_sets = TRUE;
    }

    /* Convert the template reference in "with-rsc" into a resource_set under the colocation constraint. */
    if(template_to_set(new_xml, &rsc_set_rh, XML_COLOC_ATTR_TARGET,
			    TRUE, data_set) == FALSE) {
	free_xml(new_xml);
	return FALSE;
    }

    if(rsc_set_rh) {
	if(state_rh) {
            /* A "with-rsc-role" is specified.
               Move it into the converted resource_set as a "role"" attribute. */
	    crm_xml_add(rsc_set_rh, "role", state_rh);
	    xml_remove_prop(new_xml, XML_COLOC_ATTR_TARGET_ROLE);
	}
	any_sets = TRUE;
    }

    if(any_sets) {
	crm_log_xml_trace(new_xml, "Expanded rsc_colocation...");
	*expanded_xml = new_xml;
    } else {
	free_xml(new_xml);
    }

    return TRUE;
}

gboolean
unpack_rsc_colocation(xmlNode * xml_obj, pe_working_set_t * data_set)
{
    int score_i = 0;
    xmlNode *set = NULL;
    xmlNode *last = NULL;
    gboolean any_sets = FALSE;

    xmlNode *orig_xml = NULL;
    xmlNode *expanded_xml = NULL;

    const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
    const char *score = crm_element_value(xml_obj, XML_RULE_ATTR_SCORE);

    gboolean rc = TRUE;

    if (score) {
        score_i = char2score(score);
    }

    rc = unpack_colocation_template(xml_obj, &expanded_xml, data_set);
    if(expanded_xml) {
	orig_xml = xml_obj;
	xml_obj = expanded_xml;

    } else if (rc == FALSE) {
        return FALSE;
    }
 
    for (set = __xml_first_child(xml_obj); set != NULL; set = __xml_next(set)) {
        if (crm_str_eq((const char *)set->name, XML_CONS_TAG_RSC_SET, TRUE)) {
            any_sets = TRUE;
            set = expand_idref(set, data_set->input);
            if (unpack_colocation_set(set, score_i, data_set) == FALSE) {
                return FALSE;

            } else if (last && colocate_rsc_sets(id, last, set, score_i, data_set) == FALSE) {
                return FALSE;
            }
            last = set;
        }
    }

    if(expanded_xml) {
	free_xml(expanded_xml);
	xml_obj = orig_xml;
    }

    if (any_sets == FALSE) {
        return unpack_simple_colocation(xml_obj, data_set);
    }

    return TRUE;
}

gboolean
rsc_ticket_new(const char *id, resource_t * rsc_lh, ticket_t * ticket,
               const char *state_lh, const char *loss_policy, pe_working_set_t * data_set)
{
    rsc_ticket_t *new_rsc_ticket = NULL;

    if (rsc_lh == NULL) {
        crm_config_err("No resource found for LHS %s", id);
        return FALSE;
    }

    new_rsc_ticket = calloc(1, sizeof(rsc_ticket_t));
    if (new_rsc_ticket == NULL) {
        return FALSE;
    }

    if (state_lh == NULL || safe_str_eq(state_lh, RSC_ROLE_STARTED_S)) {
        state_lh = RSC_ROLE_UNKNOWN_S;
    }

    new_rsc_ticket->id = id;
    new_rsc_ticket->ticket = ticket;
    new_rsc_ticket->rsc_lh = rsc_lh;
    new_rsc_ticket->role_lh = text2role(state_lh);

    if (safe_str_eq(loss_policy, "fence")) {
        crm_debug("On loss of ticket '%s': Fence the nodes running %s (%s)",
                  new_rsc_ticket->ticket->id, new_rsc_ticket->rsc_lh->id,
                  role2text(new_rsc_ticket->role_lh));
        new_rsc_ticket->loss_policy = loss_ticket_fence;

    } else if (safe_str_eq(loss_policy, "freeze")) {
        crm_debug("On loss of ticket '%s': Freeze %s (%s)",
                  new_rsc_ticket->ticket->id, new_rsc_ticket->rsc_lh->id,
                  role2text(new_rsc_ticket->role_lh));
        new_rsc_ticket->loss_policy = loss_ticket_freeze;

    } else if (safe_str_eq(loss_policy, "demote")) {
        crm_debug("On loss of ticket '%s': Demote %s (%s)",
                  new_rsc_ticket->ticket->id, new_rsc_ticket->rsc_lh->id,
                  role2text(new_rsc_ticket->role_lh));
        new_rsc_ticket->loss_policy = loss_ticket_demote;

    } else if (safe_str_eq(loss_policy, "stop")) {
        crm_debug("On loss of ticket '%s': Stop %s (%s)",
                  new_rsc_ticket->ticket->id, new_rsc_ticket->rsc_lh->id,
                  role2text(new_rsc_ticket->role_lh));
        new_rsc_ticket->loss_policy = loss_ticket_stop;

    } else {
        if (new_rsc_ticket->role_lh == RSC_ROLE_MASTER) {
            crm_debug("On loss of ticket '%s': Default to demote %s (%s)",
                      new_rsc_ticket->ticket->id, new_rsc_ticket->rsc_lh->id,
                      role2text(new_rsc_ticket->role_lh));
            new_rsc_ticket->loss_policy = loss_ticket_demote;

        } else {
            crm_debug("On loss of ticket '%s': Default to stop %s (%s)",
                      new_rsc_ticket->ticket->id, new_rsc_ticket->rsc_lh->id,
                      role2text(new_rsc_ticket->role_lh));
            new_rsc_ticket->loss_policy = loss_ticket_stop;
        }
    }

    crm_trace("%s (%s) ==> %s", rsc_lh->id, role2text(new_rsc_ticket->role_lh), ticket->id);

    rsc_lh->rsc_tickets = g_list_append(rsc_lh->rsc_tickets, new_rsc_ticket);

    data_set->ticket_constraints = g_list_append(data_set->ticket_constraints, new_rsc_ticket);

    return TRUE;
}

static gboolean
unpack_rsc_ticket_set(xmlNode * set, ticket_t * ticket, const char *loss_policy,
                      pe_working_set_t * data_set)
{
    xmlNode *xml_rsc = NULL;
    resource_t *resource = NULL;
    const char *set_id = ID(set);
    const char *role = crm_element_value(set, "role");

    if (set == NULL) {
        crm_config_err("No resource_set object to process.");
        return FALSE;
    }

    if (set_id == NULL) {
        crm_config_err("resource_set must have an id");
        return FALSE;
    }

    if (ticket == NULL) {
        crm_config_err("No dependented ticket specified for '%s'", set_id);
        return FALSE;
    }

    for (xml_rsc = __xml_first_child(set); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
        if (crm_str_eq((const char *)xml_rsc->name, XML_TAG_RESOURCE_REF, TRUE)) {
            EXPAND_CONSTRAINT_IDREF(set_id, resource, ID(xml_rsc));
            crm_trace("Resource '%s' depends on ticket '%s'", resource->id, ticket->id);
            rsc_ticket_new(set_id, resource, ticket, role, loss_policy, data_set);
        }
    }

    return TRUE;
}

static gboolean
unpack_simple_rsc_ticket(xmlNode * xml_obj, pe_working_set_t * data_set)
{
    const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
    const char *ticket_str = crm_element_value(xml_obj, XML_TICKET_ATTR_TICKET);
    const char *loss_policy = crm_element_value(xml_obj, XML_TICKET_ATTR_LOSS_POLICY);

    ticket_t *ticket = NULL;

    const char *id_lh = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE);
    const char *state_lh = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE_ROLE);
    const char *instance_lh = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE_INSTANCE);

    resource_t *rsc_lh = NULL;

    if (xml_obj == NULL) {
        crm_config_err("No rsc_ticket constraint object to process.");
        return FALSE;
    }

    if (id == NULL) {
        crm_config_err("%s constraint must have an id", crm_element_name(xml_obj));
        return FALSE;
    }

    if (ticket_str == NULL) {
        crm_config_err("Invalid constraint '%s': No ticket specified", id);
        return FALSE;
    } else {
        ticket = g_hash_table_lookup(data_set->tickets, ticket_str);
    }

    if (ticket == NULL) {
        crm_config_err("Invalid constraint '%s': No ticket named '%s'", id, ticket_str);
        return FALSE;
    }

    if (id_lh == NULL) {
        crm_config_err("Invalid constraint '%s': No resource specified", id);
        return FALSE;
    } else {
        rsc_lh = pe_find_resource(data_set->resources, id_lh);
    }

    if (rsc_lh == NULL) {
        crm_config_err("Invalid constraint '%s': No resource named '%s'", id, id_lh);
        return FALSE;

    } else if (instance_lh && rsc_lh->variant < pe_clone) {
        crm_config_err
            ("Invalid constraint '%s': Resource '%s' is not a clone but instance %s was requested",
             id, id_lh, instance_lh);
        return FALSE;
    }

    if (instance_lh) {
        rsc_lh = find_clone_instance(rsc_lh, instance_lh, data_set);
        if (rsc_lh == NULL) {
            crm_config_warn("Invalid constraint '%s': No instance '%s' of '%s'", id, instance_lh,
                            id_lh);
            return FALSE;
        }
    }

    rsc_ticket_new(id, rsc_lh, ticket, state_lh, loss_policy, data_set);
    return TRUE;
}

static gboolean
unpack_rsc_ticket_template(xmlNode *xml_obj, xmlNode **expanded_xml, pe_working_set_t *data_set)
{
    const char *id = NULL;
    const char *id_lh = NULL;
    const char *state_lh = NULL;

    resource_t *rsc_lh = NULL;

    xmlNode *template_rsc_set_lh = NULL;

    xmlNode *new_xml = NULL;
    xmlNode *rsc_set_lh = NULL;
    gboolean any_sets = FALSE;

    *expanded_xml = NULL;

    if(xml_obj == NULL) {
	crm_config_err("No constraint object to process.");
	return FALSE;
    }

    id = crm_element_value(xml_obj, XML_ATTR_ID);
    if(id == NULL) {
	crm_config_err("%s constraint must have an id", crm_element_name(xml_obj));
	return FALSE;
    }

    /* Attempt to expand any template references in possible resource sets. */
    expand_templates_in_sets(xml_obj, &new_xml, data_set);
    if (new_xml) {
        /* There are resource sets referencing templates. Return with the expanded XML. */
	crm_log_xml_trace(new_xml, "Expanded rsc_ticket...");
	*expanded_xml = new_xml;
	return TRUE;
    }

    id_lh = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE);
    if(id_lh == NULL) {
	return TRUE;
    }

    rsc_lh = pe_find_resource(data_set->resources, id_lh);
    if(rsc_lh) {
        /* No template is referenced. */
	return TRUE;
    }

    if(g_hash_table_lookup_extended(data_set->template_rsc_sets, id_lh,
                                    NULL, (gpointer) &template_rsc_set_lh) == FALSE) {
        crm_config_err("Invalid constraint '%s': No resource or template named '%s'", id, id_lh);
	return FALSE;

    } else if (template_rsc_set_lh == NULL) {
        crm_config_warn("Constraint '%s': No resource is derived from template '%s'", id, id_lh);
        return FALSE;
    }

    state_lh = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE_ROLE);

    new_xml = copy_xml(xml_obj);

    /* Convert the template reference in "rsc" into a resource_set under the rsc_ticket constraint. */
    if(template_to_set(new_xml, &rsc_set_lh, XML_COLOC_ATTR_SOURCE,
			    FALSE, data_set) == FALSE) {
	free_xml(new_xml);
	return FALSE;
    }

    if(rsc_set_lh) {
	if(state_lh) {
            /* A "rsc-role" is specified.
               Move it into the converted resource_set as a "role"" attribute. */
	    crm_xml_add(rsc_set_lh, "role", state_lh);
	    xml_remove_prop(new_xml, XML_COLOC_ATTR_SOURCE_ROLE);
	}
	any_sets = TRUE;
    }

    if(any_sets) {
	crm_log_xml_trace(new_xml, "Expanded rsc_ticket...");
	*expanded_xml = new_xml;
    } else {
	free_xml(new_xml);
    }

    return TRUE;
}

gboolean
unpack_rsc_ticket(xmlNode * xml_obj, pe_working_set_t * data_set)
{
    xmlNode *set = NULL;
    gboolean any_sets = FALSE;

    const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
    const char *ticket_str = crm_element_value(xml_obj, XML_TICKET_ATTR_TICKET);
    const char *loss_policy = crm_element_value(xml_obj, XML_TICKET_ATTR_LOSS_POLICY);

    ticket_t *ticket = NULL;

    xmlNode *orig_xml = NULL;
    xmlNode *expanded_xml = NULL;

    gboolean rc = TRUE;

    if (xml_obj == NULL) {
        crm_config_err("No rsc_ticket constraint object to process.");
        return FALSE;
    }

    if (id == NULL) {
        crm_config_err("%s constraint must have an id", crm_element_name(xml_obj));
        return FALSE;
    }

    if (ticket_str == NULL) {
        crm_config_err("Invalid constraint '%s': No ticket specified", id);
        return FALSE;
    } else {
        ticket = g_hash_table_lookup(data_set->tickets, ticket_str);
    }

    if (ticket == NULL) {
        ticket = ticket_new(ticket_str, data_set);
        if (ticket == NULL) {
            return FALSE;
        }
    }

    rc = unpack_rsc_ticket_template(xml_obj, &expanded_xml, data_set);
    if(expanded_xml) {
	orig_xml = xml_obj;
	xml_obj = expanded_xml;

    } else if (rc == FALSE) {
        return FALSE;
    }

    for (set = __xml_first_child(xml_obj); set != NULL; set = __xml_next(set)) {
        if (crm_str_eq((const char *)set->name, XML_CONS_TAG_RSC_SET, TRUE)) {
            any_sets = TRUE;
            set = expand_idref(set, data_set->input);
            if (unpack_rsc_ticket_set(set, ticket, loss_policy, data_set) == FALSE) {
                return FALSE;
            }
        }
    }

    if(expanded_xml) {
	free_xml(expanded_xml);
	xml_obj = orig_xml;
    }

    if (any_sets == FALSE) {
        return unpack_simple_rsc_ticket(xml_obj, data_set);
    }

    return TRUE;
}

gboolean
is_active(rsc_to_node_t * cons)
{
    return TRUE;
}

/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/pengine/rules.h>

#include <crm/common/iso8601_internal.h>
#include <crm/common/nvpair_internal.h>
#include <crm/common/rules_internal.h>
#include <crm/common/xml_internal.h>
#include <crm/pengine/internal.h>
#include <crm/pengine/rules_internal.h>

#include <sys/types.h>
#include <regex.h>

CRM_TRACE_INIT_DATA(pe_rules);

/*!
 * \brief Evaluate any rules contained by given XML element
 *
 * \param[in,out] xml          XML element to check for rules
 * \param[in]     node_hash    Node attributes to use to evaluate expressions
 * \param[in]     now          Time to use when evaluating expressions
 * \param[out]    next_change  If not NULL, set to when evaluation will change
 *
 * \return TRUE if no rules, or any of rules present is in effect, else FALSE
 */
gboolean
pe_evaluate_rules(xmlNode *ruleset, GHashTable *node_hash, crm_time_t *now,
                  crm_time_t *next_change)
{
    pe_rule_eval_data_t rule_data = {
        .node_hash = node_hash,
        .now = now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    return pe_eval_rules(ruleset, &rule_data, next_change);
}

gboolean
pe_test_rule(xmlNode *rule, GHashTable *node_hash, enum rsc_role_e role,
             crm_time_t *now, crm_time_t *next_change,
             pe_match_data_t *match_data)
{
    pe_rule_eval_data_t rule_data = {
        .node_hash = node_hash,
        .now = now,
        .match_data = match_data,
        .rsc_data = NULL,
        .op_data = NULL
    };

    return pe_eval_expr(rule, &rule_data, next_change);
}

/*!
 * \brief Evaluate one rule subelement (pass/fail)
 *
 * A rule element may contain another rule, a node attribute expression, or a
 * date expression. Given any one of those, evaluate it and return whether it
 * passed.
 *
 * \param[in,out] expr         Rule subelement XML
 * \param[in]     node_hash    Node attributes to use when evaluating expression
 * \param[in]     role         Ignored (deprecated)
 * \param[in]     now          Time to use when evaluating expression
 * \param[out]    next_change  If not NULL, set to when evaluation will change
 * \param[in]     match_data   If not NULL, resource back-references and params
 *
 * \return TRUE if expression is in effect under given conditions, else FALSE
 */
gboolean
pe_test_expression(xmlNode *expr, GHashTable *node_hash, enum rsc_role_e role,
                   crm_time_t *now, crm_time_t *next_change,
                   pe_match_data_t *match_data)
{
    pe_rule_eval_data_t rule_data = {
        .node_hash = node_hash,
        .now = now,
        .match_data = match_data,
        .rsc_data = NULL,
        .op_data = NULL
    };

    return pe_eval_subexpr(expr, &rule_data, next_change);
}

// Information about a block of nvpair elements
typedef struct sorted_set_s {
    int score;                  // This block's score for sorting
    const char *name;           // This block's ID
    const char *special_name;   // ID that should sort first
    xmlNode *attr_set;          // This block
    gboolean overwrite;         // Whether existing values will be overwritten
} sorted_set_t;

static gint
sort_pairs(gconstpointer a, gconstpointer b)
{
    const sorted_set_t *pair_a = a;
    const sorted_set_t *pair_b = b;

    if (a == NULL && b == NULL) {
        return 0;
    } else if (a == NULL) {
        return 1;
    } else if (b == NULL) {
        return -1;
    }

    if (pcmk__str_eq(pair_a->name, pair_a->special_name, pcmk__str_casei)) {
        return -1;

    } else if (pcmk__str_eq(pair_b->name, pair_a->special_name, pcmk__str_casei)) {
        return 1;
    }

    /* If we're overwriting values, we want lowest score first, so the highest
     * score is processed last; if we're not overwriting values, we want highest
     * score first, so nothing else overwrites it.
     */
    if (pair_a->score < pair_b->score) {
        return pair_a->overwrite? -1 : 1;
    } else if (pair_a->score > pair_b->score) {
        return pair_a->overwrite? 1 : -1;
    }
    return 0;
}

static void
populate_hash(xmlNode * nvpair_list, GHashTable * hash, gboolean overwrite, xmlNode * top)
{
    const char *name = NULL;
    const char *value = NULL;
    const char *old_value = NULL;
    xmlNode *list = nvpair_list;
    xmlNode *an_attr = NULL;

    if (pcmk__xe_is(list->children, PCMK__XE_ATTRIBUTES)) {
        list = list->children;
    }

    for (an_attr = pcmk__xe_first_child(list); an_attr != NULL;
         an_attr = pcmk__xe_next(an_attr)) {

        if (pcmk__xe_is(an_attr, PCMK_XE_NVPAIR)) {
            xmlNode *ref_nvpair = expand_idref(an_attr, top);

            name = crm_element_value(an_attr, PCMK_XA_NAME);
            if ((name == NULL) && (ref_nvpair != NULL)) {
                name = crm_element_value(ref_nvpair, PCMK_XA_NAME);
            }

            value = crm_element_value(an_attr, PCMK_XA_VALUE);
            if ((value == NULL) && (ref_nvpair != NULL)) {
                value = crm_element_value(ref_nvpair, PCMK_XA_VALUE);
            }

            if (name == NULL || value == NULL) {
                continue;
            }

            old_value = g_hash_table_lookup(hash, name);

            if (pcmk__str_eq(value, "#default", pcmk__str_casei)) {
                if (old_value) {
                    crm_trace("Letting %s default (removing explicit value \"%s\")",
                              name, value);
                    g_hash_table_remove(hash, name);
                }
                continue;

            } else if (old_value == NULL) {
                crm_trace("Setting %s=\"%s\"", name, value);
                pcmk__insert_dup(hash, name, value);

            } else if (overwrite) {
                crm_trace("Setting %s=\"%s\" (overwriting old value \"%s\")",
                          name, value, old_value);
                pcmk__insert_dup(hash, name, value);
            }
        }
    }
}

typedef struct unpack_data_s {
    gboolean overwrite;
    void *hash;
    crm_time_t *next_change;
    const pe_rule_eval_data_t *rule_data;
    xmlNode *top;
} unpack_data_t;

static void
unpack_attr_set(gpointer data, gpointer user_data)
{
    sorted_set_t *pair = data;
    unpack_data_t *unpack_data = user_data;

    if (!pe_eval_rules(pair->attr_set, unpack_data->rule_data,
                       unpack_data->next_change)) {
        return;
    }

    crm_trace("Adding attributes from %s (score %d) %s overwrite",
              pair->name, pair->score,
              (unpack_data->overwrite? "with" : "without"));
    populate_hash(pair->attr_set, unpack_data->hash, unpack_data->overwrite, unpack_data->top);
}

/*!
 * \internal
 * \brief Create a sorted list of nvpair blocks
 *
 * \param[in,out] top           XML document root (used to expand id-ref's)
 * \param[in]     xml_obj       XML element containing blocks of nvpair elements
 * \param[in]     set_name      If not NULL, only get blocks of this element
 * \param[in]     always_first  If not NULL, sort block with this ID as first
 *
 * \return List of sorted_set_t entries for nvpair blocks
 */
static GList *
make_pairs(xmlNode *top, const xmlNode *xml_obj, const char *set_name,
           const char *always_first, gboolean overwrite)
{
    GList *unsorted = NULL;

    if (xml_obj == NULL) {
        return NULL;
    }
    for (xmlNode *attr_set = pcmk__xe_first_child(xml_obj); attr_set != NULL;
         attr_set = pcmk__xe_next(attr_set)) {

        if ((set_name == NULL) || pcmk__xe_is(attr_set, set_name)) {
            const char *score = NULL;
            sorted_set_t *pair = NULL;
            xmlNode *expanded_attr_set = expand_idref(attr_set, top);

            if (expanded_attr_set == NULL) {
                continue; // Not possible with schema validation enabled
            }

            pair = calloc(1, sizeof(sorted_set_t));
            pair->name = pcmk__xe_id(expanded_attr_set);
            pair->special_name = always_first;
            pair->attr_set = expanded_attr_set;
            pair->overwrite = overwrite;

            score = crm_element_value(expanded_attr_set, PCMK_XA_SCORE);
            pair->score = char2score(score);

            unsorted = g_list_prepend(unsorted, pair);
        }
    }
    return g_list_sort(unsorted, sort_pairs);
}

/*!
 * \brief Extract nvpair blocks contained by an XML element into a hash table
 *
 * \param[in,out] top           XML document root (used to expand id-ref's)
 * \param[in]     xml_obj       XML element containing blocks of nvpair elements
 * \param[in]     set_name      If not NULL, only use blocks of this element
 * \param[in]     rule_data     Matching parameters to use when unpacking
 * \param[out]    hash          Where to store extracted name/value pairs
 * \param[in]     always_first  If not NULL, process block with this ID first
 * \param[in]     overwrite     Whether to replace existing values with same name
 * \param[out]    next_change   If not NULL, set to when evaluation will change
 */
void
pe_eval_nvpairs(xmlNode *top, const xmlNode *xml_obj, const char *set_name,
                const pe_rule_eval_data_t *rule_data, GHashTable *hash,
                const char *always_first, gboolean overwrite,
                crm_time_t *next_change)
{
    GList *pairs = make_pairs(top, xml_obj, set_name, always_first, overwrite);

    if (pairs) {
        unpack_data_t data = {
            .hash = hash,
            .overwrite = overwrite,
            .next_change = next_change,
            .top = top,
            .rule_data = rule_data
        };

        g_list_foreach(pairs, unpack_attr_set, &data);
        g_list_free_full(pairs, free);
    }
}

/*!
 * \brief Extract nvpair blocks contained by an XML element into a hash table
 *
 * \param[in,out] top           XML document root (used to expand id-ref's)
 * \param[in]     xml_obj       XML element containing blocks of nvpair elements
 * \param[in]     set_name      Element name to identify nvpair blocks
 * \param[in]     node_hash     Node attributes to use when evaluating rules
 * \param[out]    hash          Where to store extracted name/value pairs
 * \param[in]     always_first  If not NULL, process block with this ID first
 * \param[in]     overwrite     Whether to replace existing values with same name
 * \param[in]     now           Time to use when evaluating rules
 * \param[out]    next_change   If not NULL, set to when evaluation will change
 */
void
pe_unpack_nvpairs(xmlNode *top, const xmlNode *xml_obj, const char *set_name,
                  GHashTable *node_hash, GHashTable *hash,
                  const char *always_first, gboolean overwrite,
                  crm_time_t *now, crm_time_t *next_change)
{
    pe_rule_eval_data_t rule_data = {
        .node_hash = node_hash,
        .now = now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    pe_eval_nvpairs(top, xml_obj, set_name, &rule_data, hash,
                    always_first, overwrite, next_change);
}

/*!
 * \brief Evaluate rules
 *
 * \param[in,out] ruleset      XML possibly containing rule sub-elements
 * \param[in]     rule_data
 * \param[out]    next_change  If not NULL, set to when evaluation will change
 *
 * \return TRUE if there are no rules or
 */
gboolean
pe_eval_rules(xmlNode *ruleset, const pe_rule_eval_data_t *rule_data,
              crm_time_t *next_change)
{
    // If there are no rules, pass by default
    gboolean ruleset_default = TRUE;

    for (xmlNode *rule = first_named_child(ruleset, PCMK_XE_RULE);
         rule != NULL; rule = crm_next_same_xml(rule)) {

        ruleset_default = FALSE;
        if (pe_eval_expr(rule, rule_data, next_change)) {
            /* Only the deprecated PCMK__XE_LIFETIME element of location
             * constraints may contain more than one rule at the top level --
             * the schema limits a block of nvpairs to a single top-level rule.
             * So, this effectively means that a lifetime is active if any rule
             * it contains is active.
             */
            return TRUE;
        }
    }

    return ruleset_default;
}

/*!
 * \brief Evaluate all of a rule's expressions
 *
 * \param[in,out] rule         XML containing a rule definition or its id-ref
 * \param[in]     rule_data    Matching parameters to check against rule
 * \param[out]    next_change  If not NULL, set to when evaluation will change
 *
 * \return TRUE if \p rule_data passes \p rule, otherwise FALSE
 */
gboolean
pe_eval_expr(xmlNode *rule, const pe_rule_eval_data_t *rule_data,
             crm_time_t *next_change)
{
    xmlNode *expr = NULL;
    gboolean test = TRUE;
    gboolean empty = TRUE;
    gboolean passed = TRUE;
    gboolean do_and = TRUE;
    const char *value = NULL;

    rule = expand_idref(rule, NULL);
    if (rule == NULL) {
        return FALSE; // Not possible with schema validation enabled
    }

    value = crm_element_value(rule, PCMK_XA_BOOLEAN_OP);
    if (pcmk__str_eq(value, PCMK_VALUE_OR, pcmk__str_casei)) {
        do_and = FALSE;
        passed = FALSE;

    } else if (!pcmk__str_eq(value, PCMK_VALUE_AND,
                             pcmk__str_null_matches|pcmk__str_casei)) {
        pcmk__config_warn("Rule %s has invalid " PCMK_XA_BOOLEAN_OP
                          " value '%s', using default ('" PCMK_VALUE_AND "')",
                          pcmk__xe_id(rule), value);
    }

    crm_trace("Testing rule %s", pcmk__xe_id(rule));
    for (expr = pcmk__xe_first_child(rule); expr != NULL;
         expr = pcmk__xe_next(expr)) {

        test = pe_eval_subexpr(expr, rule_data, next_change);
        empty = FALSE;

        if (test && do_and == FALSE) {
            crm_trace("Expression %s/%s passed",
                      pcmk__xe_id(rule), pcmk__xe_id(expr));
            return TRUE;

        } else if (test == FALSE && do_and) {
            crm_trace("Expression %s/%s failed",
                      pcmk__xe_id(rule), pcmk__xe_id(expr));
            return FALSE;
        }
    }

    if (empty) {
        pcmk__config_err("Ignoring rule %s because it contains no expressions",
                         pcmk__xe_id(rule));
    }

    crm_trace("Rule %s %s", pcmk__xe_id(rule), passed ? "passed" : "failed");
    return passed;
}

/*!
 * \brief Evaluate a single rule expression, including any subexpressions
 *
 * \param[in,out] expr         XML containing a rule expression
 * \param[in]     rule_data    Matching parameters to check against expression
 * \param[out]    next_change  If not NULL, set to when evaluation will change
 *
 * \return TRUE if \p rule_data passes \p expr, otherwise FALSE
 */
gboolean
pe_eval_subexpr(xmlNode *expr, const pe_rule_eval_data_t *rule_data,
                crm_time_t *next_change)
{
    gboolean accept = FALSE;
    const char *uname = NULL;

    switch (pcmk__expression_type(expr)) {
        case pcmk__subexpr_rule:
            accept = pe_eval_expr(expr, rule_data, next_change);
            break;
        case pcmk__subexpr_attribute:
        case pcmk__subexpr_location:
            /* these expressions can never succeed if there is
             * no node to compare with
             */
            if (rule_data->node_hash != NULL) {
                accept = pe__eval_attr_expr(expr, rule_data);
            }
            break;

        case pcmk__subexpr_datetime:
            switch (pcmk__evaluate_date_expression(expr, rule_data->now,
                                                   next_change)) {
                case pcmk_rc_within_range:
                case pcmk_rc_ok:
                    accept = TRUE;
                    break;

                default:
                    accept = FALSE;
                    break;
            }
            break;

        case pcmk__subexpr_resource:
            accept = pe__eval_rsc_expr(expr, rule_data);
            break;

        case pcmk__subexpr_operation:
            accept = pe__eval_op_expr(expr, rule_data);
            break;

        default:
            CRM_CHECK(FALSE /* bad type */ , return FALSE);
            accept = FALSE;
    }
    if (rule_data->node_hash) {
        uname = g_hash_table_lookup(rule_data->node_hash, CRM_ATTR_UNAME);
    }

    crm_trace("Expression %s %s on %s",
              pcmk__xe_id(expr), (accept? "passed" : "failed"),
              pcmk__s(uname, "all nodes"));
    return accept;
}

/*!
 * \internal
 * \brief Check whether an attribute expression evaluates to \c true
 *
 * \param[in]   l_val   Value on left-hand side of comparison
 * \param[in]   r_val   Value on right-hand side of comparison
 * \param[in]   type    How to interpret the values
 * \param[in]   op      Type of comparison.
 *
 * \return  \c true if expression evaluates to \c true, \c false
 *          otherwise
 */
static bool
accept_attr_expr(const char *l_val, const char *r_val, enum pcmk__type type,
                 enum pcmk__comparison op)
{
    int cmp;

    switch (op) {
        case pcmk__comparison_defined:
            return (l_val != NULL);

        case pcmk__comparison_undefined:
            return (l_val == NULL);

        default:
            break;
    }

    cmp = pcmk__cmp_by_type(l_val, r_val, type);

    switch (op) {
        case pcmk__comparison_eq:
            return (cmp == 0);

        case pcmk__comparison_ne:
            return (cmp != 0);

        default:
            break;
    }

    if ((l_val == NULL) || (r_val == NULL)) {
        // The comparison is meaningless from this point on
        return false;
    }

    switch (op) {
        case pcmk__comparison_lt:
            return (cmp < 0);

        case pcmk__comparison_lte:
            return (cmp <= 0);

        case pcmk__comparison_gt:
            return (cmp > 0);

        case pcmk__comparison_gte:
            return (cmp >= 0);

        default: // Not possible with schema validation enabled
            return false;
    }
}

/*!
 * \internal
 * \brief Get correct value according to \c PCMK_XA_VALUE_SOURCE
 *
 * \param[in] expr_id       Rule expression ID (for logging only)
 * \param[in] value         value given in rule expression
 * \param[in] value_source  \c PCMK_XA_VALUE_SOURCE given in rule expressions
 * \param[in] match_data    If not NULL, resource back-references and params
 */
static const char *
expand_value_source(const char *expr_id, const char *value,
                    const char *value_source, const pe_match_data_t *match_data)
{
    GHashTable *table = NULL;

    if (pcmk__str_empty(value)) {
        return NULL; // value_source is irrelevant

    } else if (pcmk__str_eq(value_source, PCMK_VALUE_PARAM, pcmk__str_casei)) {
        table = match_data->params;

    } else if (pcmk__str_eq(value_source, PCMK_VALUE_META, pcmk__str_casei)) {
        table = match_data->meta;

    } else { // literal
        if (!pcmk__str_eq(value_source, PCMK_VALUE_LITERAL,
                          pcmk__str_null_matches|pcmk__str_casei)) {

            pcmk__config_warn("Expression %s has invalid " PCMK_XA_VALUE_SOURCE
                              " value '%s', using default "
                              "('" PCMK_VALUE_LITERAL "')",
                              pcmk__s(expr_id, "without ID"), value_source);
        }
        return value;
    }

    if (table == NULL) {
        return NULL;
    }
    return (const char *) g_hash_table_lookup(table, value);
}

/*!
 * \internal
 * \brief Evaluate a node attribute expression based on #uname, #id, #kind,
 *        or a generic node attribute
 *
 * \param[in] expr       XML of rule expression
 * \param[in] rule_data  The match_data and node_hash members are used
 *
 * \return TRUE if rule_data satisfies the expression, FALSE otherwise
 */
gboolean
pe__eval_attr_expr(const xmlNode *expr, const pe_rule_eval_data_t *rule_data)
{
    gboolean attr_allocated = FALSE;
    const char *h_val = NULL;

    const char *id = pcmk__xe_id(expr);
    const char *attr = crm_element_value(expr, PCMK_XA_ATTRIBUTE);
    const char *op = NULL;
    const char *type_s = crm_element_value(expr, PCMK_XA_TYPE);
    const char *value = crm_element_value(expr, PCMK_XA_VALUE);
    const char *value_source = crm_element_value(expr, PCMK_XA_VALUE_SOURCE);

    enum pcmk__comparison comparison = pcmk__comparison_unknown;
    enum pcmk__type type = pcmk__type_unknown;

    if (attr == NULL) {
        pcmk__config_err("Expression %s invalid: " PCMK_XA_ATTRIBUTE
                         " not specified", pcmk__s(id, "without ID"));
        return FALSE;
    }

    // Get and validate operation
    op = crm_element_value(expr, PCMK_XA_OPERATION);
    comparison = pcmk__parse_comparison(op);
    if (comparison == pcmk__comparison_unknown) {
        // Not possible with schema validation enabled
        if (op == NULL) {
            pcmk__config_err("Treating expression %s as not passing "
                             "because it has no " PCMK_XA_OPERATION,
                             pcmk__s(id, "without ID"));
        } else {
            pcmk__config_err("Treating expression %s as not passing "
                             "because '%s' is not a valid " PCMK_XA_OPERATION,
                             pcmk__s(id, "without ID"), op);
        }
        return FALSE;
    }

    if (rule_data->match_data != NULL) {
        // Expand any regular expression submatches (%0-%9) in attribute name
        if (rule_data->match_data->re != NULL) {
            const char *match = rule_data->match_data->re->string;
            const regmatch_t *submatches = rule_data->match_data->re->pmatch;
            const int nmatches = rule_data->match_data->re->nregs;
            char *resolved_attr = pcmk__replace_submatches(attr, match,
                                                           submatches,
                                                           nmatches);

            if (resolved_attr != NULL) {
                attr = (const char *) resolved_attr;
                attr_allocated = TRUE;
            }
        }

        // Get value appropriate to PCMK_XA_VALUE_SOURCE
        value = expand_value_source(id, value, value_source,
                                    rule_data->match_data);
    }

    if (rule_data->node_hash != NULL) {
        h_val = (const char *)g_hash_table_lookup(rule_data->node_hash, attr);
    }

    if (attr_allocated) {
        free((char *)attr);
        attr = NULL;
    }

    // Get and validate value type (after expanding value)
    type = pcmk__parse_type(type_s, comparison, h_val, value);
    if (type == pcmk__type_unknown) {
        /* Not possible with schema validation enabled
         *
         * @COMPAT When we can break behavioral backward compatibility, treat
         * the expression as not passing.
         */
        pcmk__config_warn("Non-empty node attribute values will be treated as "
                          "equal for expression %s because '%s' is not a "
                          "valid type", pcmk__s(id, "without ID"), type);
    }

    return accept_attr_expr(h_val, value, type, comparison);
}

gboolean
pe__eval_op_expr(const xmlNode *expr, const pe_rule_eval_data_t *rule_data)
{
    const char *name = crm_element_value(expr, PCMK_XA_NAME);
    const char *interval_s = crm_element_value(expr, PCMK_META_INTERVAL);
    guint interval_ms = 0U;

    crm_trace("Testing op_defaults expression: %s", pcmk__xe_id(expr));

    if (rule_data->op_data == NULL) {
        crm_trace("No operations data provided");
        return FALSE;
    }

    if (pcmk_parse_interval_spec(interval_s, &interval_ms) != pcmk_rc_ok) {
        crm_trace("Could not parse interval: %s", interval_s);
        return FALSE;
    }

    if ((interval_s != NULL) && (interval_ms != rule_data->op_data->interval)) {
        crm_trace("Interval doesn't match: %d != %d",
                  interval_ms, rule_data->op_data->interval);
        return FALSE;
    }

    if (!pcmk__str_eq(name, rule_data->op_data->op_name, pcmk__str_none)) {
        crm_trace("Name doesn't match: %s != %s", name, rule_data->op_data->op_name);
        return FALSE;
    }

    return TRUE;
}

gboolean
pe__eval_rsc_expr(const xmlNode *expr, const pe_rule_eval_data_t *rule_data)
{
    const char *class = crm_element_value(expr, PCMK_XA_CLASS);
    const char *provider = crm_element_value(expr, PCMK_XA_PROVIDER);
    const char *type = crm_element_value(expr, PCMK_XA_TYPE);

    crm_trace("Testing rsc_defaults expression: %s", pcmk__xe_id(expr));

    if (rule_data->rsc_data == NULL) {
        crm_trace("No resource data provided");
        return FALSE;
    }

    if (class != NULL &&
        !pcmk__str_eq(class, rule_data->rsc_data->standard, pcmk__str_none)) {
        crm_trace("Class doesn't match: %s != %s", class, rule_data->rsc_data->standard);
        return FALSE;
    }

    if ((provider == NULL && rule_data->rsc_data->provider != NULL) ||
        (provider != NULL && rule_data->rsc_data->provider == NULL) ||
        !pcmk__str_eq(provider, rule_data->rsc_data->provider, pcmk__str_none)) {
        crm_trace("Provider doesn't match: %s != %s", provider, rule_data->rsc_data->provider);
        return FALSE;
    }

    if (type != NULL &&
        !pcmk__str_eq(type, rule_data->rsc_data->agent, pcmk__str_none)) {
        crm_trace("Agent doesn't match: %s != %s", type, rule_data->rsc_data->agent);
        return FALSE;
    }

    return TRUE;
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/pengine/rules_compat.h>

gboolean
test_ruleset(xmlNode *ruleset, GHashTable *node_hash, crm_time_t *now)
{
    return pe_evaluate_rules(ruleset, node_hash, now, NULL);
}

gboolean
test_rule(xmlNode * rule, GHashTable * node_hash, enum rsc_role_e role, crm_time_t * now)
{
    return pe_test_rule(rule, node_hash, role, now, NULL, NULL);
}

gboolean
pe_test_rule_re(xmlNode * rule, GHashTable * node_hash, enum rsc_role_e role, crm_time_t * now, pe_re_match_data_t * re_match_data)
{
    pe_match_data_t match_data = {
                                    .re = re_match_data,
                                    .params = NULL,
                                    .meta = NULL,
                                 };
    return pe_test_rule(rule, node_hash, role, now, NULL, &match_data);
}

gboolean
pe_test_rule_full(xmlNode *rule, GHashTable *node_hash, enum rsc_role_e role,
                  crm_time_t *now, pe_match_data_t *match_data)
{
    return pe_test_rule(rule, node_hash, role, now, NULL, match_data);
}

gboolean
test_expression(xmlNode * expr, GHashTable * node_hash, enum rsc_role_e role, crm_time_t * now)
{
    return pe_test_expression(expr, node_hash, role, now, NULL, NULL);
}

gboolean
pe_test_expression_re(xmlNode * expr, GHashTable * node_hash, enum rsc_role_e role, crm_time_t * now, pe_re_match_data_t * re_match_data)
{
    pe_match_data_t match_data = {
                                    .re = re_match_data,
                                    .params = NULL,
                                    .meta = NULL,
                                 };
    return pe_test_expression(expr, node_hash, role, now, NULL, &match_data);
}

gboolean
pe_test_expression_full(xmlNode *expr, GHashTable *node_hash,
                        enum rsc_role_e role, crm_time_t *now,
                        pe_match_data_t *match_data)
{
    return pe_test_expression(expr, node_hash, role, now, NULL, match_data);
}

void
unpack_instance_attributes(xmlNode *top, xmlNode *xml_obj, const char *set_name,
                           GHashTable *node_hash, GHashTable *hash,
                           const char *always_first, gboolean overwrite,
                           crm_time_t *now)
{
    pe_rule_eval_data_t rule_data = {
        .node_hash = node_hash,
        .now = now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    pe_eval_nvpairs(top, xml_obj, set_name, &rule_data, hash, always_first,
                    overwrite, NULL);
}

enum expression_type
find_expression_type(xmlNode *expr)
{
    return pcmk__expression_type(expr);
}

char *
pe_expand_re_matches(const char *string, const pe_re_match_data_t *match_data)
{
    if (match_data == NULL) {
        return NULL;
    }
    return pcmk__replace_submatches(string, match_data->string,
                                    match_data->pmatch, match_data->nregs);
}

// LCOV_EXCL_STOP
// End deprecated API

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
 * \internal
 * \brief Map pe_rule_eval_data_t to pcmk_rule_input_t
 *
 * \param[out] new  New data struct
 * \param[in]  old  Old data struct
 */
static void
map_rule_input(pcmk_rule_input_t *new, const pe_rule_eval_data_t *old)
{
    if (old == NULL) {
        return;
    }
    new->now = old->now;
    new->node_attrs = old->node_hash;
    if (old->rsc_data != NULL) {
        new->rsc_standard = old->rsc_data->standard;
        new->rsc_provider = old->rsc_data->provider;
        new->rsc_agent = old->rsc_data->agent;
    }
    if (old->match_data != NULL) {
        new->rsc_params = old->match_data->params;
        new->rsc_meta = old->match_data->meta;
        if (old->match_data->re != NULL) {
            new->rsc_id = old->match_data->re->string;
            new->rsc_id_submatches = old->match_data->re->pmatch;
            new->rsc_id_nmatches = old->match_data->re->nregs;
        }
    }
    if (old->op_data != NULL) {
        new->op_name = old->op_data->op_name;
        new->op_interval_ms = old->op_data->interval;
    }
}

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
    pcmk_rule_input_t rule_input = {
        .now = now,
        .node_attrs = node_hash,
    };

    if (match_data != NULL) {
        rule_input.rsc_params = match_data->params;
        rule_input.rsc_meta = match_data->meta;
        if (match_data->re != NULL) {
            rule_input.rsc_id = match_data->re->string;
            rule_input.rsc_id_submatches = match_data->re->pmatch;
            rule_input.rsc_id_nmatches = match_data->re->nregs;
        }
    }
    return pcmk__evaluate_condition(expr, &rule_input,
                                    next_change) == pcmk_rc_ok;
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

    for (an_attr = pcmk__xe_first_child(list, NULL, NULL, NULL);
         an_attr != NULL; an_attr = pcmk__xe_next(an_attr)) {

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
    for (xmlNode *attr_set = pcmk__xe_first_child(xml_obj, NULL, NULL, NULL);
         attr_set != NULL; attr_set = pcmk__xe_next(attr_set)) {

        if ((set_name == NULL) || pcmk__xe_is(attr_set, set_name)) {
            const char *score = NULL;
            sorted_set_t *pair = NULL;
            xmlNode *expanded_attr_set = expand_idref(attr_set, top);

            if (expanded_attr_set == NULL) {
                continue; // Not possible with schema validation enabled
            }

            pair = pcmk__assert_alloc(1, sizeof(sorted_set_t));
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

    for (xmlNode *rule = pcmk__xe_first_child(ruleset, PCMK_XE_RULE, NULL,
                                              NULL);
         rule != NULL; rule = pcmk__xe_next_same(rule)) {

        pcmk_rule_input_t rule_input = { NULL, };

        map_rule_input(&rule_input, rule_data);
        ruleset_default = FALSE;
        if (pcmk_evaluate_rule(rule, &rule_input, next_change) == pcmk_rc_ok) {
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
    pcmk_rule_input_t rule_input = { NULL, };

    map_rule_input(&rule_input, rule_data);
    return pcmk_evaluate_rule(rule, &rule_input, next_change) == pcmk_rc_ok;
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
    pcmk_rule_input_t rule_input = { NULL, };

    map_rule_input(&rule_input, rule_data);
    return pcmk__evaluate_condition(expr, &rule_input,
                                    next_change) == pcmk_rc_ok;
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
    pcmk_rule_input_t rule_input = { NULL, };

    map_rule_input(&rule_input, rule_data);
    return pcmk__evaluate_attr_expression(expr, &rule_input) == pcmk_rc_ok;
}

gboolean
pe__eval_op_expr(const xmlNode *expr, const pe_rule_eval_data_t *rule_data)
{
    pcmk_rule_input_t rule_input = { NULL, };

    map_rule_input(&rule_input, rule_data);
    return pcmk__evaluate_op_expression(expr, &rule_input) == pcmk_rc_ok;
}

gboolean
pe__eval_rsc_expr(const xmlNode *expr, const pe_rule_eval_data_t *rule_data)
{
    pcmk_rule_input_t rule_input = { NULL, };

    map_rule_input(&rule_input, rule_data);
    return pcmk__evaluate_rsc_expression(expr, &rule_input) == pcmk_rc_ok;
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/pengine/rules_compat.h>

gboolean
pe_test_rule(xmlNode *rule, GHashTable *node_hash, enum rsc_role_e role,
             crm_time_t *now, crm_time_t *next_change,
             pe_match_data_t *match_data)
{
    pcmk_rule_input_t rule_input = {
        .node_attrs = node_hash,
        .now = now,
    };

    if (match_data != NULL) {
        rule_input.rsc_params = match_data->params;
        rule_input.rsc_meta = match_data->meta;
        if (match_data->re != NULL) {
            rule_input.rsc_id = match_data->re->string;
            rule_input.rsc_id_submatches = match_data->re->pmatch;
            rule_input.rsc_id_nmatches = match_data->re->nregs;
        }
    }
    return pcmk_evaluate_rule(rule, &rule_input, next_change) == pcmk_rc_ok;
}

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

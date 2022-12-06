/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>

#include <glib.h>

#include <crm/pengine/rules.h>
#include <crm/pengine/rules_internal.h>
#include <crm/pengine/internal.h>

#include <sys/types.h>
#include <regex.h>
#include <ctype.h>

CRM_TRACE_INIT_DATA(pe_rules);

/*!
 * \brief Evaluate any rules contained by given XML element
 *
 * \param[in]  xml          XML element to check for rules
 * \param[in]  node_hash    Node attributes to use when evaluating expressions
 * \param[in]  now          Time to use when evaluating expressions
 * \param[out] next_change  If not NULL, set to when evaluation will change
 *
 * \return TRUE if no rules, or any of rules present is in effect, else FALSE
 */
gboolean
pe_evaluate_rules(xmlNode *ruleset, GHashTable *node_hash, crm_time_t *now,
                  crm_time_t *next_change)
{
    pe_rule_eval_data_t rule_data = {
        .node_hash = node_hash,
        .role = RSC_ROLE_UNKNOWN,
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
        .role = role,
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
 * \param[in]  expr         Rule subelement XML
 * \param[in]  node_hash    Node attributes to use when evaluating expression
 * \param[in]  role         Resource role to use when evaluating expression
 * \param[in]  now          Time to use when evaluating expression
 * \param[out] next_change  If not NULL, set to when evaluation will change
 * \param[in]  match_data   If not NULL, resource back-references and params
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
        .role = role,
        .now = now,
        .match_data = match_data,
        .rsc_data = NULL,
        .op_data = NULL
    };

    return pe_eval_subexpr(expr, &rule_data, next_change);
}

enum expression_type
find_expression_type(xmlNode * expr)
{
    const char *tag = NULL;
    const char *attr = NULL;

    attr = crm_element_value(expr, XML_EXPR_ATTR_ATTRIBUTE);
    tag = crm_element_name(expr);

    if (pcmk__str_eq(tag, PCMK_XE_DATE_EXPRESSION, pcmk__str_none)) {
        return time_expr;

    } else if (pcmk__str_eq(tag, PCMK_XE_RSC_EXPRESSION, pcmk__str_none)) {
        return rsc_expr;

    } else if (pcmk__str_eq(tag, PCMK_XE_OP_EXPRESSION, pcmk__str_none)) {
        return op_expr;

    } else if (pcmk__str_eq(tag, XML_TAG_RULE, pcmk__str_none)) {
        return nested_rule;

    } else if (!pcmk__str_eq(tag, XML_TAG_EXPRESSION, pcmk__str_none)) {
        return not_expr;

    } else if (pcmk__str_any_of(attr, CRM_ATTR_UNAME, CRM_ATTR_KIND, CRM_ATTR_ID, NULL)) {
        return loc_expr;

    } else if (pcmk__str_eq(attr, CRM_ATTR_ROLE, pcmk__str_none)) {
        return role_expr;
    }

    return attr_expr;
}

/* As per the nethack rules:
 *
 * moon period = 29.53058 days ~= 30, year = 365.2422 days
 * days moon phase advances on first day of year compared to preceding year
 *      = 365.2422 - 12*29.53058 ~= 11
 * years in Metonic cycle (time until same phases fall on the same days of
 *      the month) = 18.6 ~= 19
 * moon phase on first day of year (epact) ~= (11*(year%19) + 29) % 30
 *      (29 as initial condition)
 * current phase in days = first day phase + days elapsed in year
 * 6 moons ~= 177 days
 * 177 ~= 8 reported phases * 22
 * + 11/22 for rounding
 *
 * 0-7, with 0: new, 4: full
 */

static int
phase_of_the_moon(crm_time_t * now)
{
    uint32_t epact, diy, goldn;
    uint32_t y;

    crm_time_get_ordinal(now, &y, &diy);

    goldn = (y % 19) + 1;
    epact = (11 * goldn + 18) % 30;
    if ((epact == 25 && goldn > 11) || epact == 24)
        epact++;

    return ((((((diy + epact) * 6) + 11) % 177) / 22) & 7);
}

static int
check_one(xmlNode *cron_spec, const char *xml_field, uint32_t time_field) {
    int rc = pcmk_rc_undetermined;
    const char *value = crm_element_value(cron_spec, xml_field);
    long long low, high;

    if (value == NULL) {
        /* Return pe_date_result_undetermined if the field is missing. */
        goto bail;
    }

    if (pcmk__parse_ll_range(value, &low, &high) == pcmk_rc_unknown_format) {
       goto bail;
    } else if (low == high) {
        /* A single number was given, not a range. */
        if (time_field < low) {
            rc = pcmk_rc_before_range;
        } else if (time_field > high) {
            rc = pcmk_rc_after_range;
        } else {
            rc = pcmk_rc_within_range;
        }
    } else if (low != -1 && high != -1) {
        /* This is a range with both bounds. */
        if (time_field < low) {
            rc = pcmk_rc_before_range;
        } else if (time_field > high) {
            rc = pcmk_rc_after_range;
        } else {
            rc = pcmk_rc_within_range;
        }
    } else if (low == -1) {
       /* This is a range with no starting value. */
        rc = time_field <= high ? pcmk_rc_within_range : pcmk_rc_after_range;
    } else if (high == -1) {
        /* This is a range with no ending value. */
        rc = time_field >= low ? pcmk_rc_within_range : pcmk_rc_before_range;
    }

bail:
    if (rc == pcmk_rc_within_range) {
        crm_debug("Condition '%s' in %s: passed", value, xml_field);
    } else {
        crm_debug("Condition '%s' in %s: failed", value, xml_field);
    }

    return rc;
}

static gboolean
check_passes(int rc) {
    /* _within_range is obvious.  _undetermined is a pass because
     * this is the return value if a field is not given.  In this
     * case, we just want to ignore it and check other fields to
     * see if they place some restriction on what can pass.
     */
    return rc == pcmk_rc_within_range || rc == pcmk_rc_undetermined;
}

#define CHECK_ONE(spec, name, var) do { \
    int subpart_rc = check_one(spec, name, var); \
    if (check_passes(subpart_rc) == FALSE) { \
        return subpart_rc; \
    } \
} while (0)

int
pe_cron_range_satisfied(crm_time_t * now, xmlNode * cron_spec)
{
    uint32_t h, m, s, y, d, w;

    CRM_CHECK(now != NULL, return pcmk_rc_op_unsatisfied);

    crm_time_get_gregorian(now, &y, &m, &d);
    CHECK_ONE(cron_spec, "years", y);
    CHECK_ONE(cron_spec, "months", m);
    CHECK_ONE(cron_spec, "monthdays", d);

    crm_time_get_timeofday(now, &h, &m, &s);
    CHECK_ONE(cron_spec, "hours", h);
    CHECK_ONE(cron_spec, "minutes", m);
    CHECK_ONE(cron_spec, "seconds", s);

    crm_time_get_ordinal(now, &y, &d);
    CHECK_ONE(cron_spec, "yeardays", d);

    crm_time_get_isoweek(now, &y, &w, &d);
    CHECK_ONE(cron_spec, "weekyears", y);
    CHECK_ONE(cron_spec, "weeks", w);
    CHECK_ONE(cron_spec, "weekdays", d);

    CHECK_ONE(cron_spec, "moon", phase_of_the_moon(now));

    /* If we get here, either no fields were specified (which is success), or all
     * the fields that were specified had their conditions met (which is also a
     * success).  Thus, the result is success.
     */
    return pcmk_rc_ok;
}

static void
update_field(crm_time_t *t, xmlNode *xml, const char *attr,
            void (*time_fn)(crm_time_t *, int))
{
    long long value;

    if ((pcmk__scan_ll(crm_element_value(xml, attr), &value, 0LL) == pcmk_rc_ok)
        && (value != 0LL) && (value >= INT_MIN) && (value <= INT_MAX)) {
        time_fn(t, (int) value);
    }
}

crm_time_t *
pe_parse_xml_duration(crm_time_t * start, xmlNode * duration_spec)
{
    crm_time_t *end = pcmk_copy_time(start);

    update_field(end, duration_spec, "years", crm_time_add_years);
    update_field(end, duration_spec, "months", crm_time_add_months);
    update_field(end, duration_spec, "weeks", crm_time_add_weeks);
    update_field(end, duration_spec, "days", crm_time_add_days);
    update_field(end, duration_spec, "hours", crm_time_add_hours);
    update_field(end, duration_spec, "minutes", crm_time_add_minutes);
    update_field(end, duration_spec, "seconds", crm_time_add_seconds);

    return end;
}

// Set next_change to t if t is earlier
static void
crm_time_set_if_earlier(crm_time_t *next_change, crm_time_t *t)
{
    if ((next_change != NULL) && (t != NULL)) {
        if (!crm_time_is_defined(next_change)
            || (crm_time_compare(t, next_change) < 0)) {
            crm_time_set(next_change, t);
        }
    }
}

// Information about a block of nvpair elements
typedef struct sorted_set_s {
    int score;                  // This block's score for sorting
    const char *name;           // This block's ID
    const char *special_name;   // ID that should sort first
    xmlNode *attr_set;          // This block
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

    if (pair_a->score < pair_b->score) {
        return 1;
    } else if (pair_a->score > pair_b->score) {
        return -1;
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

    name = crm_element_name(list->children);
    if (pcmk__str_eq(XML_TAG_ATTRS, name, pcmk__str_casei)) {
        list = list->children;
    }

    for (an_attr = pcmk__xe_first_child(list); an_attr != NULL;
         an_attr = pcmk__xe_next(an_attr)) {

        if (pcmk__str_eq((const char *)an_attr->name, XML_CIB_TAG_NVPAIR, pcmk__str_none)) {
            xmlNode *ref_nvpair = expand_idref(an_attr, top);

            name = crm_element_value(an_attr, XML_NVPAIR_ATTR_NAME);
            if (name == NULL) {
                name = crm_element_value(ref_nvpair, XML_NVPAIR_ATTR_NAME);
            }

            value = crm_element_value(an_attr, XML_NVPAIR_ATTR_VALUE);
            if (value == NULL) {
                value = crm_element_value(ref_nvpair, XML_NVPAIR_ATTR_VALUE);
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
                g_hash_table_insert(hash, strdup(name), strdup(value));

            } else if (overwrite) {
                crm_trace("Setting %s=\"%s\" (overwriting old value \"%s\")",
                          name, value, old_value);
                g_hash_table_replace(hash, strdup(name), strdup(value));
            }
        }
    }
}

typedef struct unpack_data_s {
    gboolean overwrite;
    void *hash;
    crm_time_t *next_change;
    pe_rule_eval_data_t *rule_data;
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
 * \param[in]  top           XML document root (used to expand id-ref's)
 * \param[in]  xml_obj       XML element containing blocks of nvpair elements
 * \param[in]  set_name      If not NULL, only get blocks of this element type
 * \param[in]  always_first  If not NULL, sort block with this ID as first
 *
 * \return List of sorted_set_t entries for nvpair blocks
 */
static GList *
make_pairs(xmlNode *top, const xmlNode *xml_obj, const char *set_name,
           const char *always_first)
{
    GList *unsorted = NULL;

    if (xml_obj == NULL) {
        return NULL;
    }
    for (xmlNode *attr_set = pcmk__xe_first_child(xml_obj); attr_set != NULL;
         attr_set = pcmk__xe_next(attr_set)) {

        if (pcmk__str_eq(set_name, (const char *) attr_set->name,
                         pcmk__str_null_matches)) {
            const char *score = NULL;
            sorted_set_t *pair = NULL;
            xmlNode *expanded_attr_set = expand_idref(attr_set, top);

            if (expanded_attr_set == NULL) {
                // Schema (if not "none") prevents this
                continue;
            }

            pair = calloc(1, sizeof(sorted_set_t));
            pair->name = ID(expanded_attr_set);
            pair->special_name = always_first;
            pair->attr_set = expanded_attr_set;

            score = crm_element_value(expanded_attr_set, XML_RULE_ATTR_SCORE);
            pair->score = char2score(score);

            unsorted = g_list_prepend(unsorted, pair);
        }
    }
    return g_list_sort(unsorted, sort_pairs);
}

/*!
 * \internal
 * \brief Extract nvpair blocks contained by an XML element into a hash table
 *
 * \param[in]  top           XML document root (used to expand id-ref's)
 * \param[in]  xml_obj       XML element containing blocks of nvpair elements
 * \param[in]  set_name      If not NULL, only use blocks of this element type
 * \param[out] hash          Where to store extracted name/value pairs
 * \param[in]  always_first  If not NULL, process block with this ID first
 * \param[in]  overwrite     Whether to replace existing values with same name
 * \param[in]  rule_data     Matching parameters to use when unpacking
 * \param[out] next_change   If not NULL, set to when rule evaluation will change
 * \param[in]  unpack_func   Function to call to unpack each block
 */
static void
unpack_nvpair_blocks(xmlNode *top, const xmlNode *xml_obj, const char *set_name,
                     void *hash, const char *always_first, gboolean overwrite,
                     pe_rule_eval_data_t *rule_data, crm_time_t *next_change,
                     GFunc unpack_func)
{
    GList *pairs = make_pairs(top, xml_obj, set_name, always_first);

    if (pairs) {
        unpack_data_t data = {
            .hash = hash,
            .overwrite = overwrite,
            .next_change = next_change,
            .top = top,
            .rule_data = rule_data
        };

        g_list_foreach(pairs, unpack_func, &data);
        g_list_free_full(pairs, free);
    }
}

void
pe_eval_nvpairs(xmlNode *top, const xmlNode *xml_obj, const char *set_name,
                pe_rule_eval_data_t *rule_data, GHashTable *hash,
                const char *always_first, gboolean overwrite,
                crm_time_t *next_change)
{
    unpack_nvpair_blocks(top, xml_obj, set_name, hash, always_first,
                         overwrite, rule_data, next_change, unpack_attr_set);
}

/*!
 * \brief Extract nvpair blocks contained by an XML element into a hash table
 *
 * \param[in]  top           XML document root (used to expand id-ref's)
 * \param[in]  xml_obj       XML element containing blocks of nvpair elements
 * \param[in]  set_name      Element name to identify nvpair blocks
 * \param[in]  node_hash     Node attributes to use when evaluating rules
 * \param[out] hash          Where to store extracted name/value pairs
 * \param[in]  always_first  If not NULL, process block with this ID first
 * \param[in]  overwrite     Whether to replace existing values with same name
 * \param[in]  now           Time to use when evaluating rules
 * \param[out] next_change   If not NULL, set to when rule evaluation will change
 */
void
pe_unpack_nvpairs(xmlNode *top, xmlNode *xml_obj, const char *set_name,
                  GHashTable *node_hash, GHashTable *hash,
                  const char *always_first, gboolean overwrite,
                  crm_time_t *now, crm_time_t *next_change)
{
    pe_rule_eval_data_t rule_data = {
        .node_hash = node_hash,
        .role = RSC_ROLE_UNKNOWN,
        .now = now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    pe_eval_nvpairs(top, xml_obj, set_name, &rule_data, hash,
                    always_first, overwrite, next_change);
}

/*!
 * \brief Expand any regular expression submatches (%0-%9) in a string
 *
 * \param[in] string      String possibly containing submatch variables
 * \param[in] match_data  If not NULL, regular expression matches
 *
 * \return Newly allocated string identical to \p string with submatches
 *         expanded, or NULL if there were no matches
 */
char *
pe_expand_re_matches(const char *string, const pe_re_match_data_t *match_data)
{
    size_t len = 0;
    int i;
    const char *p, *last_match_index;
    char *p_dst, *result = NULL;

    if (pcmk__str_empty(string) || !match_data) {
        return NULL;
    }

    p = last_match_index = string;

    while (*p) {
        if (*p == '%' && *(p + 1) && isdigit(*(p + 1))) {
            i = *(p + 1) - '0';
            if (match_data->nregs >= i && match_data->pmatch[i].rm_so != -1 &&
                match_data->pmatch[i].rm_eo > match_data->pmatch[i].rm_so) {
                len += p - last_match_index + (match_data->pmatch[i].rm_eo - match_data->pmatch[i].rm_so);
                last_match_index = p + 2;
            }
            p++;
        }
        p++;
    }
    len += p - last_match_index + 1;

    /* FIXME: Excessive? */
    if (len - 1 <= 0) {
        return NULL;
    }

    p_dst = result = calloc(1, len);
    p = string;

    while (*p) {
        if (*p == '%' && *(p + 1) && isdigit(*(p + 1))) {
            i = *(p + 1) - '0';
            if (match_data->nregs >= i && match_data->pmatch[i].rm_so != -1 &&
                match_data->pmatch[i].rm_eo > match_data->pmatch[i].rm_so) {
                /* rm_eo can be equal to rm_so, but then there is nothing to do */
                int match_len = match_data->pmatch[i].rm_eo - match_data->pmatch[i].rm_so;
                memcpy(p_dst, match_data->string + match_data->pmatch[i].rm_so, match_len);
                p_dst += match_len;
            }
            p++;
        } else {
            *(p_dst) = *(p);
            p_dst++;
        }
        p++;
    }

    return result;
}

gboolean
pe_eval_rules(xmlNode *ruleset, pe_rule_eval_data_t *rule_data, crm_time_t *next_change)
{
    // If there are no rules, pass by default
    gboolean ruleset_default = TRUE;

    for (xmlNode *rule = first_named_child(ruleset, XML_TAG_RULE);
         rule != NULL; rule = crm_next_same_xml(rule)) {

        ruleset_default = FALSE;
        if (pe_eval_expr(rule, rule_data, next_change)) {
            /* Only the deprecated "lifetime" element of location constraints
             * may contain more than one rule at the top level -- the schema
             * limits a block of nvpairs to a single top-level rule. So, this
             * effectively means that a lifetime is active if any rule it
             * contains is active.
             */
            return TRUE;
        }
    }

    return ruleset_default;
}

gboolean
pe_eval_expr(xmlNode *rule, pe_rule_eval_data_t *rule_data, crm_time_t *next_change)
{
    xmlNode *expr = NULL;
    gboolean test = TRUE;
    gboolean empty = TRUE;
    gboolean passed = TRUE;
    gboolean do_and = TRUE;
    const char *value = NULL;

    rule = expand_idref(rule, NULL);
    value = crm_element_value(rule, XML_RULE_ATTR_BOOLEAN_OP);
    if (pcmk__str_eq(value, "or", pcmk__str_casei)) {
        do_and = FALSE;
        passed = FALSE;
    }

    crm_trace("Testing rule %s", ID(rule));
    for (expr = pcmk__xe_first_child(rule); expr != NULL;
         expr = pcmk__xe_next(expr)) {

        test = pe_eval_subexpr(expr, rule_data, next_change);
        empty = FALSE;

        if (test && do_and == FALSE) {
            crm_trace("Expression %s/%s passed", ID(rule), ID(expr));
            return TRUE;

        } else if (test == FALSE && do_and) {
            crm_trace("Expression %s/%s failed", ID(rule), ID(expr));
            return FALSE;
        }
    }

    if (empty) {
        crm_err("Invalid Rule %s: rules must contain at least one expression", ID(rule));
    }

    crm_trace("Rule %s %s", ID(rule), passed ? "passed" : "failed");
    return passed;
}

gboolean
pe_eval_subexpr(xmlNode *expr, pe_rule_eval_data_t *rule_data, crm_time_t *next_change)
{
    gboolean accept = FALSE;
    const char *uname = NULL;

    switch (find_expression_type(expr)) {
        case nested_rule:
            accept = pe_eval_expr(expr, rule_data, next_change);
            break;
        case attr_expr:
        case loc_expr:
            /* these expressions can never succeed if there is
             * no node to compare with
             */
            if (rule_data->node_hash != NULL) {
                accept = pe__eval_attr_expr(expr, rule_data);
            }
            break;

        case time_expr:
            switch (pe__eval_date_expr(expr, rule_data, next_change)) {
                case pcmk_rc_within_range:
                case pcmk_rc_ok:
                    accept = TRUE;
                    break;

                default:
                    accept = FALSE;
                    break;
            }
            break;

        case role_expr:
            accept = pe__eval_role_expr(expr, rule_data);
            break;

        case rsc_expr:
            accept = pe__eval_rsc_expr(expr, rule_data);
            break;

        case op_expr:
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
              ID(expr), accept ? "passed" : "failed", uname ? uname : "all nodes");
    return accept;
}

/*!
 * \internal
 * \brief   Compare two values in a rule's node attribute expression
 *
 * \param[in]   l_val   Value on left-hand side of comparison
 * \param[in]   r_val   Value on right-hand side of comparison
 * \param[in]   type    How to interpret the values (allowed values:
 *                      \c "string", \c "integer", \c "number",
 *                      \c "version", \c NULL)
 * \param[in]   op      Type of comparison
 *
 * \return  -1 if <tt>(l_val < r_val)</tt>,
 *           0 if <tt>(l_val == r_val)</tt>,
 *           1 if <tt>(l_val > r_val)</tt>
 */
static int
compare_attr_expr_vals(const char *l_val, const char *r_val, const char *type,
                       const char *op)
{
    int cmp = 0;

    if (l_val != NULL && r_val != NULL) {
        if (type == NULL) {
            if (pcmk__strcase_any_of(op, "lt", "lte", "gt", "gte", NULL)) {
                if (pcmk__char_in_any_str('.', l_val, r_val, NULL)) {
                    type = "number";
                } else {
                    type = "integer";
                }

            } else {
                type = "string";
            }
            crm_trace("Defaulting to %s based comparison for '%s' op", type, op);
        }

        if (pcmk__str_eq(type, "string", pcmk__str_casei)) {
            cmp = strcasecmp(l_val, r_val);

        } else if (pcmk__str_eq(type, "integer", pcmk__str_casei)) {
            long long l_val_num;
            int rc1 = pcmk__scan_ll(l_val, &l_val_num, 0LL);

            long long r_val_num;
            int rc2 = pcmk__scan_ll(r_val, &r_val_num, 0LL);

            if ((rc1 == pcmk_rc_ok) && (rc2 == pcmk_rc_ok)) {
                if (l_val_num < r_val_num) {
                    cmp = -1;
                } else if (l_val_num > r_val_num) {
                    cmp = 1;
                } else {
                    cmp = 0;
                }

            } else {
                crm_debug("Integer parse error. Comparing %s and %s as strings",
                          l_val, r_val);
                cmp = compare_attr_expr_vals(l_val, r_val, "string", op);
            }

        } else if (pcmk__str_eq(type, "number", pcmk__str_casei)) {
            double l_val_num;
            double r_val_num;

            int rc1 = pcmk__scan_double(l_val, &l_val_num, NULL, NULL);
            int rc2 = pcmk__scan_double(r_val, &r_val_num, NULL, NULL);

            if (rc1 == pcmk_rc_ok && rc2 == pcmk_rc_ok) {
                if (l_val_num < r_val_num) {
                    cmp = -1;
                } else if (l_val_num > r_val_num) {
                    cmp = 1;
                } else {
                    cmp = 0;
                }

            } else {
                crm_debug("Floating-point parse error. Comparing %s and %s as "
                          "strings", l_val, r_val);
                cmp = compare_attr_expr_vals(l_val, r_val, "string", op);
            }

        } else if (pcmk__str_eq(type, "version", pcmk__str_casei)) {
            cmp = compare_version(l_val, r_val);

        }

    } else if (l_val == NULL && r_val == NULL) {
        cmp = 0;
    } else if (r_val == NULL) {
        cmp = 1;
    } else {    // l_val == NULL && r_val != NULL
        cmp = -1;
    }

    return cmp;
}

/*!
 * \internal
 * \brief   Check whether an attribute expression evaluates to \c true
 *
 * \param[in]   l_val   Value on left-hand side of comparison
 * \param[in]   r_val   Value on right-hand side of comparison
 * \param[in]   type    How to interpret the values (allowed values:
 *                      \c "string", \c "integer", \c "number",
 *                      \c "version", \c NULL)
 * \param[in]   op      Type of comparison.
 *
 * \return  \c true if expression evaluates to \c true, \c false
 *          otherwise
 */
static bool
accept_attr_expr(const char *l_val, const char *r_val, const char *type,
                 const char *op)
{
    int cmp;

    if (pcmk__str_eq(op, "defined", pcmk__str_casei)) {
        return (l_val != NULL);

    } else if (pcmk__str_eq(op, "not_defined", pcmk__str_casei)) {
        return (l_val == NULL);

    }

    cmp = compare_attr_expr_vals(l_val, r_val, type, op);

    if (pcmk__str_eq(op, "eq", pcmk__str_casei)) {
        return (cmp == 0);

    } else if (pcmk__str_eq(op, "ne", pcmk__str_casei)) {
        return (cmp != 0);

    } else if (l_val == NULL || r_val == NULL) {
        // The comparison is meaningless from this point on
        return false;

    } else if (pcmk__str_eq(op, "lt", pcmk__str_casei)) {
        return (cmp < 0);

    } else if (pcmk__str_eq(op, "lte", pcmk__str_casei)) {
        return (cmp <= 0);

    } else if (pcmk__str_eq(op, "gt", pcmk__str_casei)) {
        return (cmp > 0);

    } else if (pcmk__str_eq(op, "gte", pcmk__str_casei)) {
        return (cmp >= 0);
    }

    return false;   // Should never reach this point
}

/*!
 * \internal
 * \brief Get correct value according to value-source
 *
 * \param[in] value         value given in rule expression
 * \param[in] value_source  value-source given in rule expressions
 * \param[in] match_data    If not NULL, resource back-references and params
 */
static const char *
expand_value_source(const char *value, const char *value_source,
                    pe_match_data_t *match_data)
{
    GHashTable *table = NULL;

    if (pcmk__str_empty(value)) {
        return NULL; // value_source is irrelevant

    } else if (pcmk__str_eq(value_source, "param", pcmk__str_casei)) {
        table = match_data->params;

    } else if (pcmk__str_eq(value_source, "meta", pcmk__str_casei)) {
        table = match_data->meta;

    } else { // literal
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
pe__eval_attr_expr(xmlNodePtr expr, pe_rule_eval_data_t *rule_data)
{
    gboolean attr_allocated = FALSE;
    const char *h_val = NULL;

    const char *op = NULL;
    const char *type = NULL;
    const char *attr = NULL;
    const char *value = NULL;
    const char *value_source = NULL;

    attr = crm_element_value(expr, XML_EXPR_ATTR_ATTRIBUTE);
    op = crm_element_value(expr, XML_EXPR_ATTR_OPERATION);
    value = crm_element_value(expr, XML_EXPR_ATTR_VALUE);
    type = crm_element_value(expr, XML_EXPR_ATTR_TYPE);
    value_source = crm_element_value(expr, XML_EXPR_ATTR_VALUE_SOURCE);

    if (attr == NULL) {
        pe_err("Expression %s invalid: " XML_EXPR_ATTR_ATTRIBUTE
               " not specified", pcmk__s(ID(expr), "without ID"));
        return FALSE;
    } else if (op == NULL) {
        pe_err("Expression %s invalid: " XML_EXPR_ATTR_OPERATION
               " not specified", pcmk__s(ID(expr), "without ID"));
    }

    if (rule_data->match_data != NULL) {
        // Expand any regular expression submatches (%0-%9) in attribute name
        if (rule_data->match_data->re != NULL) {
            char *resolved_attr = pe_expand_re_matches(attr, rule_data->match_data->re);

            if (resolved_attr != NULL) {
                attr = (const char *) resolved_attr;
                attr_allocated = TRUE;
            }
        }

        // Get value appropriate to value-source
        value = expand_value_source(value, value_source, rule_data->match_data);
    }

    if (rule_data->node_hash != NULL) {
        h_val = (const char *)g_hash_table_lookup(rule_data->node_hash, attr);
    }

    if (attr_allocated) {
        free((char *)attr);
        attr = NULL;
    }

    return accept_attr_expr(h_val, value, type, op);
}

/*!
 * \internal
 * \brief Evaluate a date_expression
 *
 * \param[in]  expr         XML of rule expression
 * \param[in]  rule_data    Only the now member is used
 * \param[out] next_change  If not NULL, set to when evaluation will change
 *
 * \return Standard Pacemaker return code
 */
int
pe__eval_date_expr(xmlNodePtr expr, pe_rule_eval_data_t *rule_data, crm_time_t *next_change)
{
    crm_time_t *start = NULL;
    crm_time_t *end = NULL;
    const char *value = NULL;
    const char *op = crm_element_value(expr, "operation");

    xmlNode *duration_spec = NULL;
    xmlNode *date_spec = NULL;

    // "undetermined" will also be returned for parsing errors
    int rc = pcmk_rc_undetermined;

    crm_trace("Testing expression: %s", ID(expr));

    duration_spec = first_named_child(expr, "duration");
    date_spec = first_named_child(expr, "date_spec");

    value = crm_element_value(expr, "start");
    if (value != NULL) {
        start = crm_time_new(value);
    }
    value = crm_element_value(expr, "end");
    if (value != NULL) {
        end = crm_time_new(value);
    }

    if (start != NULL && end == NULL && duration_spec != NULL) {
        end = pe_parse_xml_duration(start, duration_spec);
    }

    if (pcmk__str_eq(op, "in_range", pcmk__str_null_matches | pcmk__str_casei)) {
        if ((start == NULL) && (end == NULL)) {
            // in_range requires at least one of start or end
        } else if ((start != NULL) && (crm_time_compare(rule_data->now, start) < 0)) {
            rc = pcmk_rc_before_range;
            crm_time_set_if_earlier(next_change, start);
        } else if ((end != NULL) && (crm_time_compare(rule_data->now, end) > 0)) {
            rc = pcmk_rc_after_range;
        } else {
            rc = pcmk_rc_within_range;
            if (end && next_change) {
                // Evaluation doesn't change until second after end
                crm_time_add_seconds(end, 1);
                crm_time_set_if_earlier(next_change, end);
            }
        }

    } else if (pcmk__str_eq(op, "date_spec", pcmk__str_casei)) {
        rc = pe_cron_range_satisfied(rule_data->now, date_spec);
        // @TODO set next_change appropriately

    } else if (pcmk__str_eq(op, "gt", pcmk__str_casei)) {
        if (start == NULL) {
            // gt requires start
        } else if (crm_time_compare(rule_data->now, start) > 0) {
            rc = pcmk_rc_within_range;
        } else {
            rc = pcmk_rc_before_range;

            // Evaluation doesn't change until second after start
            crm_time_add_seconds(start, 1);
            crm_time_set_if_earlier(next_change, start);
        }

    } else if (pcmk__str_eq(op, "lt", pcmk__str_casei)) {
        if (end == NULL) {
            // lt requires end
        } else if (crm_time_compare(rule_data->now, end) < 0) {
            rc = pcmk_rc_within_range;
            crm_time_set_if_earlier(next_change, end);
        } else {
            rc = pcmk_rc_after_range;
        }
    }

    crm_time_free(start);
    crm_time_free(end);
    return rc;
}

gboolean
pe__eval_op_expr(xmlNodePtr expr, pe_rule_eval_data_t *rule_data) {
    const char *name = crm_element_value(expr, XML_NVPAIR_ATTR_NAME);
    const char *interval_s = crm_element_value(expr, XML_LRM_ATTR_INTERVAL);
    guint interval;

    crm_trace("Testing op_defaults expression: %s", ID(expr));

    if (rule_data->op_data == NULL) {
        crm_trace("No operations data provided");
        return FALSE;
    }

    interval = crm_parse_interval_spec(interval_s);
    if (interval == 0 && errno != 0) {
        crm_trace("Could not parse interval: %s", interval_s);
        return FALSE;
    }

    if (interval_s != NULL && interval != rule_data->op_data->interval) {
        crm_trace("Interval doesn't match: %d != %d", interval, rule_data->op_data->interval);
        return FALSE;
    }

    if (!pcmk__str_eq(name, rule_data->op_data->op_name, pcmk__str_none)) {
        crm_trace("Name doesn't match: %s != %s", name, rule_data->op_data->op_name);
        return FALSE;
    }

    return TRUE;
}

/*!
 * \internal
 * \brief Evaluate a node attribute expression based on #role
 *
 * \param[in] expr       XML of rule expression
 * \param[in] rule_data  Only the role member is used
 *
 * \return TRUE if rule_data->role satisfies the expression, FALSE otherwise
 */
gboolean
pe__eval_role_expr(xmlNodePtr expr, pe_rule_eval_data_t *rule_data)
{
    gboolean accept = FALSE;
    const char *op = NULL;
    const char *value = NULL;

    if (rule_data->role == RSC_ROLE_UNKNOWN) {
        return accept;
    }

    value = crm_element_value(expr, XML_EXPR_ATTR_VALUE);
    op = crm_element_value(expr, XML_EXPR_ATTR_OPERATION);

    if (pcmk__str_eq(op, "defined", pcmk__str_casei)) {
        if (rule_data->role > RSC_ROLE_STARTED) {
            accept = TRUE;
        }

    } else if (pcmk__str_eq(op, "not_defined", pcmk__str_casei)) {
        if ((rule_data->role > RSC_ROLE_UNKNOWN)
            && (rule_data->role < RSC_ROLE_UNPROMOTED)) {
            accept = TRUE;
        }

    } else if (pcmk__str_eq(op, "eq", pcmk__str_casei)) {
        if (text2role(value) == rule_data->role) {
            accept = TRUE;
        }

    } else if (pcmk__str_eq(op, "ne", pcmk__str_casei)) {
        // Test "ne" only with promotable clone roles
        if ((rule_data->role > RSC_ROLE_UNKNOWN)
            && (rule_data->role < RSC_ROLE_UNPROMOTED)) {
            accept = FALSE;

        } else if (text2role(value) != rule_data->role) {
            accept = TRUE;
        }
    }
    return accept;
}

gboolean
pe__eval_rsc_expr(xmlNodePtr expr, pe_rule_eval_data_t *rule_data)
{
    const char *class = crm_element_value(expr, XML_AGENT_ATTR_CLASS);
    const char *provider = crm_element_value(expr, XML_AGENT_ATTR_PROVIDER);
    const char *type = crm_element_value(expr, XML_EXPR_ATTR_TYPE);

    crm_trace("Testing rsc_defaults expression: %s", ID(expr));

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
        .role = RSC_ROLE_UNKNOWN,
        .now = now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    unpack_nvpair_blocks(top, xml_obj, set_name, hash, always_first,
                         overwrite, &rule_data, NULL, unpack_attr_set);
}

// LCOV_EXCL_STOP
// End deprecated API

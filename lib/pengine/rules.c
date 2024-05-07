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

static gint
sort_pairs(gconstpointer a, gconstpointer b, gpointer user_data)
{
    const xmlNode *pair_a = a;
    const xmlNode *pair_b = b;
    pcmk__nvpair_unpack_t *unpack_data = user_data;

    const char *score = NULL;
    int score_a = 0;
    int score_b = 0;

    if (a == NULL && b == NULL) {
        return 0;
    } else if (a == NULL) {
        return 1;
    } else if (b == NULL) {
        return -1;
    }

    if (pcmk__str_eq(pcmk__xe_id(pair_a), unpack_data->first_id,
                     pcmk__str_none)) {
        return -1;

    } else if (pcmk__str_eq(pcmk__xe_id(pair_b), unpack_data->first_id,
                            pcmk__str_none)) {
        return 1;
    }

    score = crm_element_value(pair_a, PCMK_XA_SCORE);
    score_a = char2score(score);

    score = crm_element_value(pair_b, PCMK_XA_SCORE);
    score_b = char2score(score);

    /* If we're overwriting values, we want lowest score first, so the highest
     * score is processed last; if we're not overwriting values, we want highest
     * score first, so nothing else overwrites it.
     */
    if (score_a < score_b) {
        return unpack_data->overwrite? -1 : 1;
    } else if (score_a > score_b) {
        return unpack_data->overwrite? 1 : -1;
    }
    return 0;
}

static void
populate_hash(xmlNode *nvpair_list, GHashTable *hash, bool overwrite)
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
            xmlNode *ref_nvpair = expand_idref(an_attr, NULL);

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
                // @COMPAT Deprecated since 2.1.8
                pcmk__config_warn("Support for setting meta-attributes (such "
                                  "as %s) to the explicit value '#default' is "
                                  "deprecated and will be removed in a future "
                                  "release", name);
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

static void
unpack_attr_set(gpointer data, gpointer user_data)
{
    xmlNode *pair = data;
    pcmk__nvpair_unpack_t *unpack_data = user_data;

    if (pcmk__evaluate_rules(pair, &(unpack_data->rule_input),
                             unpack_data->next_change) != pcmk_rc_ok) {
        return;
    }

    crm_trace("Adding name/value pairs from %s %s overwrite",
              pcmk__xe_id(pair), (unpack_data->overwrite? "with" : "without"));
    populate_hash(pair, unpack_data->values, unpack_data->overwrite);
}

/*!
 * \internal
 * \brief Create a sorted list of nvpair blocks
 *
 * \param[in]     xml_obj       XML element containing blocks of nvpair elements
 * \param[in]     set_name      If not NULL, only get blocks of this element
 *
 * \return List of XML blocks of name/value pairs
 */
static GList *
make_pairs(const xmlNode *xml_obj, const char *set_name)
{
    GList *unsorted = NULL;

    if (xml_obj == NULL) {
        return NULL;
    }
    for (xmlNode *attr_set = pcmk__xe_first_child(xml_obj, NULL, NULL, NULL);
         attr_set != NULL; attr_set = pcmk__xe_next(attr_set)) {

        if ((set_name == NULL) || pcmk__xe_is(attr_set, set_name)) {
            xmlNode *expanded_attr_set = expand_idref(attr_set, NULL);

            if (expanded_attr_set == NULL) {
                continue; // Not possible with schema validation enabled
            }
            unsorted = g_list_prepend(unsorted, expanded_attr_set);
        }
    }
    return unsorted;
}

/*!
 * \brief Extract nvpair blocks contained by an XML element into a hash table
 *
 * \param[in,out] top           Ignored
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
    GList *pairs = make_pairs(xml_obj, set_name);

    if (pairs) {
        pcmk__nvpair_unpack_t data = {
            .values = hash,
            .first_id = always_first,
            .overwrite = overwrite,
            .next_change = next_change,
        };

        map_rule_input(&(data.rule_input), rule_data);

        pairs = g_list_sort_with_data(pairs, sort_pairs, &data);
        g_list_foreach(pairs, unpack_attr_set, &data);
        g_list_free(pairs);
    }
}

/*!
 * \brief Extract nvpair blocks contained by an XML element into a hash table
 *
 * \param[in,out] top           Ignored
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

    pe_eval_nvpairs(NULL, xml_obj, set_name, &rule_data, hash,
                    always_first, overwrite, next_change);
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/pengine/rules_compat.h>

gboolean
pe_eval_rules(xmlNode *ruleset, const pe_rule_eval_data_t *rule_data,
              crm_time_t *next_change)
{
    pcmk_rule_input_t rule_input = { NULL, };

    map_rule_input(&rule_input, rule_data);
    return pcmk__evaluate_rules(ruleset, &rule_input,
                                next_change) == pcmk_rc_ok;
}

gboolean
pe_evaluate_rules(xmlNode *ruleset, GHashTable *node_hash, crm_time_t *now,
                  crm_time_t *next_change)
{
    pcmk_rule_input_t rule_input = {
        .node_attrs = node_hash,
        .now = now,
    };

    return pcmk__evaluate_rules(ruleset, &rule_input, next_change);
}

static gboolean
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

// LCOV_EXCL_STOP
// End deprecated API

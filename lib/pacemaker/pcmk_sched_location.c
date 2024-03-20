/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <glib.h>

#include <crm/crm.h>
#include <crm/common/rules_internal.h>
#include <crm/pengine/status.h>
#include <crm/pengine/rules.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

static int
get_node_score(const char *rule, const char *score, bool raw,
               pcmk_node_t *node, pcmk_resource_t *rsc)
{
    int score_f = 0;

    if (score == NULL) {
        pcmk__config_warn("Rule %s: no score specified (assuming 0)", rule);

    } else if (raw) {
        score_f = char2score(score);

    } else {
        const char *target = NULL;
        const char *attr_score = NULL;

        target = g_hash_table_lookup(rsc->meta,
                                     PCMK_META_CONTAINER_ATTRIBUTE_TARGET);

        attr_score = pcmk__node_attr(node, score, target,
                                     pcmk__rsc_node_current);
        if (attr_score == NULL) {
            crm_debug("Rule %s: %s did not have a value for %s",
                      rule, pcmk__node_name(node), score);
            score_f = -PCMK_SCORE_INFINITY;

        } else {
            crm_debug("Rule %s: %s had value %s for %s",
                      rule, pcmk__node_name(node), attr_score, score);
            score_f = char2score(attr_score);
        }
    }
    return score_f;
}

/*!
 * \internal
 * \brief Parse a role configuration for a location constraint
 *
 * \param[in]  role_spec  Role specification
 * \param[out] role       Where to store parsed role
 *
 * \return true if role specification is valid, otherwise false
 */
static bool
parse_location_role(const char *role_spec, enum rsc_role_e *role)
{
    if (role_spec == NULL) {
        *role = pcmk_role_unknown;
        return true;
    }

    *role = pcmk_parse_role(role_spec);
    switch (*role) {
        case pcmk_role_unknown:
            return false;

        case pcmk_role_started:
        case pcmk_role_unpromoted:
            /* Any promotable clone instance cannot be promoted without being in
             * the unpromoted role first. Therefore, any constraint for the
             * started or unpromoted role applies to every role.
             */
            *role = pcmk_role_unknown;
            break;

        default:
            break;
    }
    return true;
}

/*!
 * \internal
 * \brief Generate a location constraint from a rule
 *
 * \param[in,out] rsc            Resource that constraint is for
 * \param[in]     rule_xml       Rule XML (sub-element of location constraint)
 * \param[in]     discovery      Value of \c PCMK_XA_RESOURCE_DISCOVERY for
 *                               constraint
 * \param[out]    next_change    Where to set when rule evaluation will change
 * \param[in]     re_match_data  Regular expression submatches
 *
 * \return New location constraint if rule is valid, otherwise NULL
 */
static pcmk__location_t *
generate_location_rule(pcmk_resource_t *rsc, xmlNode *rule_xml,
                       const char *discovery, crm_time_t *next_change,
                       pe_re_match_data_t *re_match_data)
{
    const char *rule_id = NULL;
    const char *score = NULL;
    const char *boolean = NULL;
    const char *role_spec = NULL;

    GList *iter = NULL;
    GList *nodes = NULL;

    bool raw_score = true;
    bool score_allocated = false;

    pcmk__location_t *location_rule = NULL;
    enum rsc_role_e role = pcmk_role_unknown;
    enum pcmk__combine combine = pcmk__combine_unknown;

    rule_xml = expand_idref(rule_xml, rsc->cluster->input);
    if (rule_xml == NULL) {
        return NULL; // Error already logged
    }

    rule_id = crm_element_value(rule_xml, PCMK_XA_ID);
    boolean = crm_element_value(rule_xml, PCMK_XA_BOOLEAN_OP);
    role_spec = crm_element_value(rule_xml, PCMK_XA_ROLE);

    if (parse_location_role(role_spec, &role)) {
        crm_trace("Setting rule %s role filter to %s", rule_id, role_spec);
    } else {
        pcmk__config_err("Ignoring rule %s: Invalid " PCMK_XA_ROLE " '%s'",
                         rule_id, role_spec);
        return NULL;
    }

    crm_trace("Processing location constraint rule %s", rule_id);

    score = crm_element_value(rule_xml, PCMK_XA_SCORE);
    if (score == NULL) {
        score = crm_element_value(rule_xml, PCMK_XA_SCORE_ATTRIBUTE);
        if (score != NULL) {
            raw_score = false;
        }
    }

    combine = pcmk__parse_combine(boolean);
    switch (combine) {
        case pcmk__combine_and:
        case pcmk__combine_or:
            break;

        default:
            /* @COMPAT When we can break behavioral backward compatibility,
             * return NULL
             */
            pcmk__config_warn("Location constraint rule %s has invalid "
                              PCMK_XA_BOOLEAN_OP " value '%s', using default "
                              "'" PCMK_VALUE_AND "'",
                              rule_id, boolean);
            combine = pcmk__combine_and;
            break;
    }

    location_rule = pcmk__new_location(rule_id, rsc, 0, discovery, NULL);
    if (location_rule == NULL) {
        return NULL; // Error already logged
    }
    location_rule->role_filter = role;

    if ((re_match_data != NULL) && (re_match_data->nregs > 0)
        && (re_match_data->pmatch[0].rm_so != -1) && !raw_score) {

        char *result = pcmk__replace_submatches(score, re_match_data->string,
                                                re_match_data->pmatch,
                                                re_match_data->nregs);

        if (result != NULL) {
            score = result;
            score_allocated = true;
        }
    }

    if (combine == pcmk__combine_and) {
        nodes = pcmk__copy_node_list(rsc->cluster->nodes, true);
        for (iter = nodes; iter != NULL; iter = iter->next) {
            pcmk_node_t *node = iter->data;

            node->weight = get_node_score(rule_id, score, raw_score, node, rsc);
        }
    }

    for (iter = rsc->cluster->nodes; iter != NULL; iter = iter->next) {
        int rc = pcmk_rc_ok;
        int score_f = 0;
        pcmk_node_t *node = iter->data;
        pcmk_rule_input_t rule_input = {
            .now = rsc->cluster->now,
            .node_attrs = node->details->attrs,
            .rsc_params = pe_rsc_params(rsc, node, rsc->cluster),
            .rsc_meta = rsc->meta,
        };

        if (re_match_data != NULL) {
            rule_input.rsc_id = re_match_data->string;
            rule_input.rsc_id_submatches = re_match_data->pmatch;
            rule_input.rsc_id_nmatches = re_match_data->nregs;
        }

        rc = pcmk_evaluate_rule(rule_xml, &rule_input, next_change);

        crm_trace("Rule %s %s on %s",
                  pcmk__xe_id(rule_xml),
                  ((rc == pcmk_rc_ok)? "passed" : "failed"),
                  pcmk__node_name(node));

        score_f = get_node_score(rule_id, score, raw_score, node, rsc);

        if (rc == pcmk_rc_ok) {
            pcmk_node_t *local = pe_find_node_id(nodes, node->details->id);

            if ((local == NULL) && (combine == pcmk__combine_and)) {
                continue;

            } else if (local == NULL) {
                local = pe__copy_node(node);
                nodes = g_list_append(nodes, local);
            }

            if (combine == pcmk__combine_or) {
                local->weight = pcmk__add_scores(local->weight, score_f);
            }
            crm_trace("%s has score %s after %s", pcmk__node_name(node),
                      pcmk_readable_score(local->weight), rule_id);

        } else if (combine == pcmk__combine_and) {
            // Remove it
            pcmk_node_t *delete = pe_find_node_id(nodes, node->details->id);

            if (delete != NULL) {
                nodes = g_list_remove(nodes, delete);
                crm_trace("%s did not match", pcmk__node_name(node));
            }
            free(delete);
        }
    }

    if (score_allocated) {
        free((char *)score);
    }

    location_rule->nodes = nodes;
    if (location_rule->nodes == NULL) {
        crm_trace("No matching nodes for location constraint rule %s", rule_id);
        return NULL;
    } else {
        crm_trace("Location constraint rule %s matched %d nodes",
                  rule_id, g_list_length(location_rule->nodes));
    }
    return location_rule;
}

static void
unpack_rsc_location(xmlNode *xml_obj, pcmk_resource_t *rsc,
                    const char *role_spec, const char *score,
                    pe_re_match_data_t *re_match_data)
{
    const char *rsc_id = crm_element_value(xml_obj, PCMK_XA_RSC);
    const char *id = crm_element_value(xml_obj, PCMK_XA_ID);
    const char *node = crm_element_value(xml_obj, PCMK_XE_NODE);
    const char *discovery = crm_element_value(xml_obj,
                                              PCMK_XA_RESOURCE_DISCOVERY);

    if (rsc == NULL) {
        pcmk__config_warn("Ignoring constraint '%s' because resource '%s' "
                          "does not exist", id, rsc_id);
        return;
    }

    if (score == NULL) {
        score = crm_element_value(xml_obj, PCMK_XA_SCORE);
    }

    if ((node != NULL) && (score != NULL)) {
        int score_i = char2score(score);
        pcmk_node_t *match = pe_find_node(rsc->cluster->nodes, node);
        enum rsc_role_e role = pcmk_role_unknown;
        pcmk__location_t *location = NULL;

        if (!match) {
            return;
        }

        if (role_spec == NULL) {
            role_spec = crm_element_value(xml_obj, PCMK_XA_ROLE);
        }
        if (parse_location_role(role_spec, &role)) {
            crm_trace("Setting location constraint %s role filter: %s",
                      id, role_spec);
        } else {
            /* @COMPAT The previous behavior of creating the constraint ignoring
             * the role is retained for now, but we should ignore the entire
             * constraint when we can break backward compatibility.
             */
            pcmk__config_err("Ignoring role in constraint %s: "
                             "Invalid value '%s'", id, role_spec);
        }

        location = pcmk__new_location(id, rsc, score_i, discovery, match);
        if (location == NULL) {
            return; // Error already logged
        }
        location->role_filter = role;

    } else {
        bool empty = true;
        crm_time_t *next_change = crm_time_new_undefined();

        /* This loop is logically parallel to pe_evaluate_rules(), except
         * instead of checking whether any rule is active, we set up location
         * constraints for each active rule.
         *
         * @COMPAT When we can break backward compatibility, limit location
         * constraints to a single rule, for consistency with other contexts.
         * Since a rule may contain other rules, this does not prohibit any
         * existing use cases.
         */
        for (xmlNode *rule_xml = pcmk__xe_first_child(xml_obj, PCMK_XE_RULE,
                                                      NULL, NULL);
             rule_xml != NULL; rule_xml = pcmk__xe_next_same(rule_xml)) {

            if (empty) {
                empty = false;
            } else {
                pcmk__warn_once(pcmk__wo_location_rules,
                                "Support for multiple " PCMK_XE_RULE
                                " elements in a location constraint is "
                                "deprecated and will be removed in a future "
                                "release (use a single new rule combining the "
                                "previous rules with " PCMK_XA_BOOLEAN_OP
                                " set to '" PCMK_VALUE_OR "' instead)");
            }
            generate_location_rule(rsc, rule_xml, discovery, next_change,
                                   re_match_data);
        }

        if (empty) {
            pcmk__config_err("Ignoring constraint '%s' because it contains "
                             "no rules", id);
        }

        /* If there is a point in the future when the evaluation of a rule will
         * change, make sure the scheduler is re-run by that time.
         */
        if (crm_time_is_defined(next_change)) {
            time_t t = (time_t) crm_time_get_seconds_since_epoch(next_change);

            pe__update_recheck_time(t, rsc->cluster,
                                    "location rule evaluation");
        }
        crm_time_free(next_change);
    }
}

static void
unpack_simple_location(xmlNode *xml_obj, pcmk_scheduler_t *scheduler)
{
    const char *id = crm_element_value(xml_obj, PCMK_XA_ID);
    const char *value = crm_element_value(xml_obj, PCMK_XA_RSC);

    if (value) {
        pcmk_resource_t *rsc;

        rsc = pcmk__find_constraint_resource(scheduler->resources, value);
        unpack_rsc_location(xml_obj, rsc, NULL, NULL, NULL);
    }

    value = crm_element_value(xml_obj, PCMK_XA_RSC_PATTERN);
    if (value) {
        regex_t *r_patt = pcmk__assert_alloc(1, sizeof(regex_t));
        bool invert = false;

        if (value[0] == '!') {
            value++;
            invert = true;
        }

        if (regcomp(r_patt, value, REG_EXTENDED) != 0) {
            pcmk__config_err("Ignoring constraint '%s' because "
                             PCMK_XA_RSC_PATTERN
                             " has invalid value '%s'", id, value);
            free(r_patt);
            return;
        }

        for (GList *iter = scheduler->resources; iter != NULL;
             iter = iter->next) {

            pcmk_resource_t *r = iter->data;
            int nregs = 0;
            regmatch_t *pmatch = NULL;
            int status;

            if (r_patt->re_nsub > 0) {
                nregs = r_patt->re_nsub + 1;
            } else {
                nregs = 1;
            }
            pmatch = pcmk__assert_alloc(nregs, sizeof(regmatch_t));

            status = regexec(r_patt, r->id, nregs, pmatch, 0);

            if (!invert && (status == 0)) {
                pe_re_match_data_t re_match_data = {
                                                .string = r->id,
                                                .nregs = nregs,
                                                .pmatch = pmatch
                                               };

                crm_debug("'%s' matched '%s' for %s", r->id, value, id);
                unpack_rsc_location(xml_obj, r, NULL, NULL, &re_match_data);

            } else if (invert && (status != 0)) {
                crm_debug("'%s' is an inverted match of '%s' for %s",
                          r->id, value, id);
                unpack_rsc_location(xml_obj, r, NULL, NULL, NULL);

            } else {
                crm_trace("'%s' does not match '%s' for %s", r->id, value, id);
            }

            free(pmatch);
        }

        regfree(r_patt);
        free(r_patt);
    }
}

// \return Standard Pacemaker return code
static int
unpack_location_tags(xmlNode *xml_obj, xmlNode **expanded_xml,
                     pcmk_scheduler_t *scheduler)
{
    const char *id = NULL;
    const char *rsc_id = NULL;
    const char *state = NULL;
    pcmk_resource_t *rsc = NULL;
    pcmk_tag_t *tag = NULL;
    xmlNode *rsc_set = NULL;

    *expanded_xml = NULL;

    CRM_CHECK(xml_obj != NULL, return EINVAL);

    id = pcmk__xe_id(xml_obj);
    if (id == NULL) {
        pcmk__config_err("Ignoring <%s> constraint without " PCMK_XA_ID,
                         xml_obj->name);
        return pcmk_rc_unpack_error;
    }

    // Check whether there are any resource sets with template or tag references
    *expanded_xml = pcmk__expand_tags_in_sets(xml_obj, scheduler);
    if (*expanded_xml != NULL) {
        crm_log_xml_trace(*expanded_xml, "Expanded " PCMK_XE_RSC_LOCATION);
        return pcmk_rc_ok;
    }

    rsc_id = crm_element_value(xml_obj, PCMK_XA_RSC);
    if (rsc_id == NULL) {
        return pcmk_rc_ok;
    }

    if (!pcmk__valid_resource_or_tag(scheduler, rsc_id, &rsc, &tag)) {
        pcmk__config_err("Ignoring constraint '%s' because '%s' is not a "
                         "valid resource or tag", id, rsc_id);
        return pcmk_rc_unpack_error;

    } else if (rsc != NULL) {
        // No template is referenced
        return pcmk_rc_ok;
    }

    state = crm_element_value(xml_obj, PCMK_XA_ROLE);

    *expanded_xml = pcmk__xml_copy(NULL, xml_obj);

    /* Convert any template or tag reference into constraint
     * PCMK_XE_RESOURCE_SET
     */
    if (!pcmk__tag_to_set(*expanded_xml, &rsc_set, PCMK_XA_RSC,
                          false, scheduler)) {
        free_xml(*expanded_xml);
        *expanded_xml = NULL;
        return pcmk_rc_unpack_error;
    }

    if (rsc_set != NULL) {
        if (state != NULL) {
            /* Move PCMK_XA_RSC_ROLE into converted PCMK_XE_RESOURCE_SET as
             * PCMK_XA_ROLE attribute
             */
            crm_xml_add(rsc_set, PCMK_XA_ROLE, state);
            pcmk__xe_remove_attr(*expanded_xml, PCMK_XA_ROLE);
        }
        crm_log_xml_trace(*expanded_xml, "Expanded " PCMK_XE_RSC_LOCATION);

    } else {
        // No sets
        free_xml(*expanded_xml);
        *expanded_xml = NULL;
    }

    return pcmk_rc_ok;
}

// \return Standard Pacemaker return code
static int
unpack_location_set(xmlNode *location, xmlNode *set,
                    pcmk_scheduler_t *scheduler)
{
    xmlNode *xml_rsc = NULL;
    pcmk_resource_t *resource = NULL;
    const char *set_id;
    const char *role;
    const char *local_score;

    CRM_CHECK(set != NULL, return EINVAL);

    set_id = pcmk__xe_id(set);
    if (set_id == NULL) {
        pcmk__config_err("Ignoring " PCMK_XE_RESOURCE_SET " without "
                         PCMK_XA_ID " in constraint '%s'",
                         pcmk__s(pcmk__xe_id(location), "(missing ID)"));
        return pcmk_rc_unpack_error;
    }

    role = crm_element_value(set, PCMK_XA_ROLE);
    local_score = crm_element_value(set, PCMK_XA_SCORE);

    for (xml_rsc = pcmk__xe_first_child(set, PCMK_XE_RESOURCE_REF, NULL, NULL);
         xml_rsc != NULL; xml_rsc = pcmk__xe_next_same(xml_rsc)) {

        resource = pcmk__find_constraint_resource(scheduler->resources,
                                                  pcmk__xe_id(xml_rsc));
        if (resource == NULL) {
            pcmk__config_err("%s: No resource found for %s",
                             set_id, pcmk__xe_id(xml_rsc));
            return pcmk_rc_unpack_error;
        }

        unpack_rsc_location(location, resource, role, local_score, NULL);
    }

    return pcmk_rc_ok;
}

void
pcmk__unpack_location(xmlNode *xml_obj, pcmk_scheduler_t *scheduler)
{
    xmlNode *set = NULL;
    bool any_sets = false;

    xmlNode *orig_xml = NULL;
    xmlNode *expanded_xml = NULL;

    if (unpack_location_tags(xml_obj, &expanded_xml, scheduler) != pcmk_rc_ok) {
        return;
    }

    if (expanded_xml) {
        orig_xml = xml_obj;
        xml_obj = expanded_xml;
    }

    for (set = pcmk__xe_first_child(xml_obj, PCMK_XE_RESOURCE_SET, NULL, NULL);
         set != NULL; set = pcmk__xe_next_same(set)) {

        any_sets = true;
        set = expand_idref(set, scheduler->input);
        if ((set == NULL) // Configuration error, message already logged
            || (unpack_location_set(xml_obj, set, scheduler) != pcmk_rc_ok)) {

            if (expanded_xml) {
                free_xml(expanded_xml);
            }
            return;
        }
    }

    if (expanded_xml) {
        free_xml(expanded_xml);
        xml_obj = orig_xml;
    }

    if (!any_sets) {
        unpack_simple_location(xml_obj, scheduler);
    }
}

/*!
 * \internal
 * \brief Add a new location constraint to scheduler data
 *
 * \param[in]     id             XML ID of location constraint
 * \param[in,out] rsc            Resource in location constraint
 * \param[in]     node_score     Constraint score
 * \param[in]     discover_mode  Resource discovery option for constraint
 * \param[in]     node           Node in constraint (or NULL if rule-based)
 *
 * \return Newly allocated location constraint
 * \note The result will be added to the cluster (via \p rsc) and should not be
 *       freed separately.
 */
pcmk__location_t *
pcmk__new_location(const char *id, pcmk_resource_t *rsc,
                   int node_score, const char *discover_mode, pcmk_node_t *node)
{
    pcmk__location_t *new_con = NULL;

    if (id == NULL) {
        pcmk__config_err("Invalid constraint: no ID specified");
        return NULL;

    } else if (rsc == NULL) {
        pcmk__config_err("Invalid constraint %s: no resource specified", id);
        return NULL;

    } else if (node == NULL) {
        CRM_CHECK(node_score == 0, return NULL);
    }

    new_con = calloc(1, sizeof(pcmk__location_t));
    if (new_con != NULL) {
        new_con->id = strdup(id);
        new_con->rsc = rsc;
        new_con->nodes = NULL;
        new_con->role_filter = pcmk_role_unknown;

        if (pcmk__str_eq(discover_mode, PCMK_VALUE_ALWAYS,
                         pcmk__str_null_matches|pcmk__str_casei)) {
            new_con->discover_mode = pcmk_probe_always;

        } else if (pcmk__str_eq(discover_mode, PCMK_VALUE_NEVER,
                                pcmk__str_casei)) {
            new_con->discover_mode = pcmk_probe_never;

        } else if (pcmk__str_eq(discover_mode, PCMK_VALUE_EXCLUSIVE,
                                pcmk__str_casei)) {
            new_con->discover_mode = pcmk_probe_exclusive;
            rsc->exclusive_discover = TRUE;

        } else {
            pcmk__config_err("Invalid " PCMK_XA_RESOURCE_DISCOVERY " value %s "
                             "in location constraint", discover_mode);
        }

        if (node != NULL) {
            pcmk_node_t *copy = pe__copy_node(node);

            copy->weight = node_score;
            new_con->nodes = g_list_prepend(NULL, copy);
        }

        rsc->cluster->placement_constraints = g_list_prepend(
            rsc->cluster->placement_constraints, new_con);
        rsc->rsc_location = g_list_prepend(rsc->rsc_location, new_con);
    }

    return new_con;
}

/*!
 * \internal
 * \brief Apply all location constraints
 *
 * \param[in,out] scheduler  Scheduler data
 */
void
pcmk__apply_locations(pcmk_scheduler_t *scheduler)
{
    for (GList *iter = scheduler->placement_constraints;
         iter != NULL; iter = iter->next) {
        pcmk__location_t *location = iter->data;

        location->rsc->cmds->apply_location(location->rsc, location);
    }
}

/*!
 * \internal
 * \brief Apply a location constraint to a resource's allowed node scores
 *
 * \param[in,out] rsc         Resource to apply constraint to
 * \param[in,out] location    Location constraint to apply
 *
 * \note This does not consider the resource's children, so the resource's
 *       apply_location() method should be used instead in most cases.
 */
void
pcmk__apply_location(pcmk_resource_t *rsc, pcmk__location_t *location)
{
    bool need_role = false;

    CRM_ASSERT((rsc != NULL) && (location != NULL));

    // If a role was specified, ensure constraint is applicable
    need_role = (location->role_filter > pcmk_role_unknown);
    if (need_role && (location->role_filter != rsc->next_role)) {
        pcmk__rsc_trace(rsc,
                        "Not applying %s to %s because role will be %s not %s",
                        location->id, rsc->id, pcmk_role_text(rsc->next_role),
                        pcmk_role_text(location->role_filter));
        return;
    }

    if (location->nodes == NULL) {
        pcmk__rsc_trace(rsc, "Not applying %s to %s because no nodes match",
                        location->id, rsc->id);
        return;
    }

    pcmk__rsc_trace(rsc, "Applying %s%s%s to %s", location->id,
                    (need_role? " for role " : ""),
                    (need_role? pcmk_role_text(location->role_filter) : ""),
                    rsc->id);

    for (GList *iter = location->nodes; iter != NULL; iter = iter->next) {
        pcmk_node_t *node = iter->data;
        pcmk_node_t *allowed_node = g_hash_table_lookup(rsc->allowed_nodes,
                                                        node->details->id);

        if (allowed_node == NULL) {
            pcmk__rsc_trace(rsc, "* = %d on %s",
                            node->weight, pcmk__node_name(node));
            allowed_node = pe__copy_node(node);
            g_hash_table_insert(rsc->allowed_nodes,
                                (gpointer) allowed_node->details->id,
                                allowed_node);
        } else {
            pcmk__rsc_trace(rsc, "* + %d on %s",
                            node->weight, pcmk__node_name(node));
            allowed_node->weight = pcmk__add_scores(allowed_node->weight,
                                                    node->weight);
        }

        if (allowed_node->rsc_discover_mode < location->discover_mode) {
            if (location->discover_mode == pcmk_probe_exclusive) {
                rsc->exclusive_discover = TRUE;
            }
            /* exclusive > never > always... always is default */
            allowed_node->rsc_discover_mode = location->discover_mode;
        }
    }
}

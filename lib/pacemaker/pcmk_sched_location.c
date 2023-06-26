/*
 * Copyright 2004-2023 the Pacemaker project contributors
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
#include <crm/pengine/status.h>
#include <crm/pengine/rules.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

static int
get_node_score(const char *rule, const char *score, bool raw,
               pe_node_t *node, pe_resource_t *rsc)
{
    int score_f = 0;

    if (score == NULL) {
        pe_err("Rule %s: no score specified.  Assuming 0.", rule);

    } else if (raw) {
        score_f = char2score(score);

    } else {
        const char *attr_score = NULL;

        attr_score = pe__node_attribute_calculated(node, score, rsc,
                                                   pe__rsc_node_current, false);

        if (attr_score == NULL) {
            crm_debug("Rule %s: %s did not have a value for %s",
                      rule, pe__node_name(node), score);
            score_f = -INFINITY;

        } else {
            crm_debug("Rule %s: %s had value %s for %s",
                      rule, pe__node_name(node), attr_score, score);
            score_f = char2score(attr_score);
        }
    }
    return score_f;
}

static pe__location_t *
generate_location_rule(pe_resource_t *rsc, xmlNode *rule_xml,
                       const char *discovery, crm_time_t *next_change,
                       pe_re_match_data_t *re_match_data)
{
    const char *rule_id = NULL;
    const char *score = NULL;
    const char *boolean = NULL;
    const char *role = NULL;

    GList *iter = NULL;
    GList *nodes = NULL;

    bool do_and = true;
    bool accept = true;
    bool raw_score = true;
    bool score_allocated = false;

    pe__location_t *location_rule = NULL;

    rule_xml = expand_idref(rule_xml, rsc->cluster->input);
    if (rule_xml == NULL) {
        return NULL;
    }

    rule_id = crm_element_value(rule_xml, XML_ATTR_ID);
    boolean = crm_element_value(rule_xml, XML_RULE_ATTR_BOOLEAN_OP);
    role = crm_element_value(rule_xml, XML_RULE_ATTR_ROLE);

    crm_trace("Processing rule: %s", rule_id);

    if ((role != NULL) && (text2role(role) == RSC_ROLE_UNKNOWN)) {
        pe_err("Bad role specified for %s: %s", rule_id, role);
        return NULL;
    }

    score = crm_element_value(rule_xml, XML_RULE_ATTR_SCORE);
    if (score == NULL) {
        score = crm_element_value(rule_xml, XML_RULE_ATTR_SCORE_ATTRIBUTE);
        if (score != NULL) {
            raw_score = false;
        }
    }
    if (pcmk__str_eq(boolean, "or", pcmk__str_casei)) {
        do_and = false;
    }

    location_rule = pcmk__new_location(rule_id, rsc, 0, discovery, NULL);

    if (location_rule == NULL) {
        return NULL;
    }

    if ((re_match_data != NULL) && (re_match_data->nregs > 0)
        && (re_match_data->pmatch[0].rm_so != -1) && !raw_score) {

        char *result = pe_expand_re_matches(score, re_match_data);

        if (result != NULL) {
            score = result;
            score_allocated = true;
        }
    }

    if (role != NULL) {
        crm_trace("Setting role filter: %s", role);
        location_rule->role_filter = text2role(role);
        if (location_rule->role_filter == RSC_ROLE_UNPROMOTED) {
            /* Any promotable clone cannot be promoted without being in the
             * unpromoted role first. Ergo, any constraint for the unpromoted
             * role applies to every role.
             */
            location_rule->role_filter = RSC_ROLE_UNKNOWN;
        }
    }
    if (do_and) {
        nodes = pcmk__copy_node_list(rsc->cluster->nodes, true);
        for (iter = nodes; iter != NULL; iter = iter->next) {
            pe_node_t *node = iter->data;

            node->weight = get_node_score(rule_id, score, raw_score, node, rsc);
        }
    }

    for (iter = rsc->cluster->nodes; iter != NULL; iter = iter->next) {
        int score_f = 0;
        pe_node_t *node = iter->data;
        pe_match_data_t match_data = {
            .re = re_match_data,
            .params = pe_rsc_params(rsc, node, rsc->cluster),
            .meta = rsc->meta,
        };

        accept = pe_test_rule(rule_xml, node->details->attrs, RSC_ROLE_UNKNOWN,
                              rsc->cluster->now, next_change, &match_data);

        crm_trace("Rule %s %s on %s", ID(rule_xml), accept? "passed" : "failed",
                  pe__node_name(node));

        score_f = get_node_score(rule_id, score, raw_score, node, rsc);

        if (accept) {
            pe_node_t *local = pe_find_node_id(nodes, node->details->id);

            if ((local == NULL) && do_and) {
                continue;

            } else if (local == NULL) {
                local = pe__copy_node(node);
                nodes = g_list_append(nodes, local);
            }

            if (!do_and) {
                local->weight = pcmk__add_scores(local->weight, score_f);
            }
            crm_trace("%s has score %s after %s", pe__node_name(node),
                      pcmk_readable_score(local->weight), rule_id);

        } else if (do_and && !accept) {
            // Remove it
            pe_node_t *delete = pe_find_node_id(nodes, node->details->id);

            if (delete != NULL) {
                nodes = g_list_remove(nodes, delete);
                crm_trace("%s did not match", pe__node_name(node));
            }
            free(delete);
        }
    }

    if (score_allocated) {
        free((char *)score);
    }

    location_rule->node_list_rh = nodes;
    if (location_rule->node_list_rh == NULL) {
        crm_trace("No matching nodes for rule %s", rule_id);
        return NULL;
    }

    crm_trace("%s: %d nodes matched",
              rule_id, g_list_length(location_rule->node_list_rh));
    return location_rule;
}

static void
unpack_rsc_location(xmlNode *xml_obj, pe_resource_t *rsc, const char *role,
                    const char *score, pe_re_match_data_t *re_match_data)
{
    pe__location_t *location = NULL;
    const char *rsc_id = crm_element_value(xml_obj, XML_LOC_ATTR_SOURCE);
    const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
    const char *node = crm_element_value(xml_obj, XML_CIB_TAG_NODE);
    const char *discovery = crm_element_value(xml_obj,
                                              XML_LOCATION_ATTR_DISCOVERY);

    if (rsc == NULL) {
        pcmk__config_warn("Ignoring constraint '%s' because resource '%s' "
                          "does not exist", id, rsc_id);
        return;
    }

    if (score == NULL) {
        score = crm_element_value(xml_obj, XML_RULE_ATTR_SCORE);
    }

    if ((node != NULL) && (score != NULL)) {
        int score_i = char2score(score);
        pe_node_t *match = pe_find_node(rsc->cluster->nodes, node);

        if (!match) {
            return;
        }
        location = pcmk__new_location(id, rsc, score_i, discovery, match);

    } else {
        bool empty = true;
        crm_time_t *next_change = crm_time_new_undefined();

        /* This loop is logically parallel to pe_evaluate_rules(), except
         * instead of checking whether any rule is active, we set up location
         * constraints for each active rule.
         */
        for (xmlNode *rule_xml = first_named_child(xml_obj, XML_TAG_RULE);
             rule_xml != NULL; rule_xml = crm_next_same_xml(rule_xml)) {
            empty = false;
            crm_trace("Unpacking %s/%s", id, ID(rule_xml));
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

            pe__update_recheck_time(t, rsc->cluster);
        }
        crm_time_free(next_change);
        return;
    }

    if (role == NULL) {
        role = crm_element_value(xml_obj, XML_RULE_ATTR_ROLE);
    }

    if ((location != NULL) && (role != NULL)) {
        if (text2role(role) == RSC_ROLE_UNKNOWN) {
            pe_err("Invalid constraint %s: Bad role %s", id, role);
            return;

        } else {
            enum rsc_role_e r = text2role(role);
            switch (r) {
                case RSC_ROLE_UNKNOWN:
                case RSC_ROLE_STARTED:
                case RSC_ROLE_UNPROMOTED:
                    /* Applies to all */
                    location->role_filter = RSC_ROLE_UNKNOWN;
                    break;
                default:
                    location->role_filter = r;
                    break;
            }
        }
    }
}

static void
unpack_simple_location(xmlNode *xml_obj, pe_working_set_t *data_set)
{
    const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
    const char *value = crm_element_value(xml_obj, XML_LOC_ATTR_SOURCE);

    if (value) {
        pe_resource_t *rsc;

        rsc = pcmk__find_constraint_resource(data_set->resources, value);
        unpack_rsc_location(xml_obj, rsc, NULL, NULL, NULL);
    }

    value = crm_element_value(xml_obj, XML_LOC_ATTR_SOURCE_PATTERN);
    if (value) {
        regex_t *r_patt = calloc(1, sizeof(regex_t));
        bool invert = false;

        if (value[0] == '!') {
            value++;
            invert = true;
        }

        if (regcomp(r_patt, value, REG_EXTENDED) != 0) {
            pcmk__config_err("Ignoring constraint '%s' because "
                             XML_LOC_ATTR_SOURCE_PATTERN
                             " has invalid value '%s'", id, value);
            free(r_patt);
            return;
        }

        for (GList *iter = data_set->resources; iter != NULL;
             iter = iter->next) {

            pe_resource_t *r = iter->data;
            int nregs = 0;
            regmatch_t *pmatch = NULL;
            int status;

            if (r_patt->re_nsub > 0) {
                nregs = r_patt->re_nsub + 1;
            } else {
                nregs = 1;
            }
            pmatch = calloc(nregs, sizeof(regmatch_t));

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
                     pe_working_set_t *data_set)
{
    const char *id = NULL;
    const char *rsc_id = NULL;
    const char *state = NULL;
    pe_resource_t *rsc = NULL;
    pe_tag_t *tag = NULL;
    xmlNode *rsc_set = NULL;

    *expanded_xml = NULL;

    CRM_CHECK(xml_obj != NULL, return EINVAL);

    id = ID(xml_obj);
    if (id == NULL) {
        pcmk__config_err("Ignoring <%s> constraint without " XML_ATTR_ID,
                         crm_element_name(xml_obj));
        return pcmk_rc_unpack_error;
    }

    // Check whether there are any resource sets with template or tag references
    *expanded_xml = pcmk__expand_tags_in_sets(xml_obj, data_set);
    if (*expanded_xml != NULL) {
        crm_log_xml_trace(*expanded_xml, "Expanded rsc_location");
        return pcmk_rc_ok;
    }

    rsc_id = crm_element_value(xml_obj, XML_LOC_ATTR_SOURCE);
    if (rsc_id == NULL) {
        return pcmk_rc_ok;
    }

    if (!pcmk__valid_resource_or_tag(data_set, rsc_id, &rsc, &tag)) {
        pcmk__config_err("Ignoring constraint '%s' because '%s' is not a "
                         "valid resource or tag", id, rsc_id);
        return pcmk_rc_unpack_error;

    } else if (rsc != NULL) {
        // No template is referenced
        return pcmk_rc_ok;
    }

    state = crm_element_value(xml_obj, XML_RULE_ATTR_ROLE);

    *expanded_xml = copy_xml(xml_obj);

    // Convert any template or tag reference into constraint resource_set
    if (!pcmk__tag_to_set(*expanded_xml, &rsc_set, XML_LOC_ATTR_SOURCE,
                          false, data_set)) {
        free_xml(*expanded_xml);
        *expanded_xml = NULL;
        return pcmk_rc_unpack_error;
    }

    if (rsc_set != NULL) {
        if (state != NULL) {
            // Move "rsc-role" into converted resource_set as "role" attribute
            crm_xml_add(rsc_set, "role", state);
            xml_remove_prop(*expanded_xml, XML_RULE_ATTR_ROLE);
        }
        crm_log_xml_trace(*expanded_xml, "Expanded rsc_location");

    } else {
        // No sets
        free_xml(*expanded_xml);
        *expanded_xml = NULL;
    }

    return pcmk_rc_ok;
}

// \return Standard Pacemaker return code
static int
unpack_location_set(xmlNode *location, xmlNode *set, pe_working_set_t *data_set)
{
    xmlNode *xml_rsc = NULL;
    pe_resource_t *resource = NULL;
    const char *set_id;
    const char *role;
    const char *local_score;

    CRM_CHECK(set != NULL, return EINVAL);

    set_id = ID(set);
    if (set_id == NULL) {
        pcmk__config_err("Ignoring " XML_CONS_TAG_RSC_SET " without "
                         XML_ATTR_ID " in constraint '%s'",
                         pcmk__s(ID(location), "(missing ID)"));
        return pcmk_rc_unpack_error;
    }

    role = crm_element_value(set, "role");
    local_score = crm_element_value(set, XML_RULE_ATTR_SCORE);

    for (xml_rsc = first_named_child(set, XML_TAG_RESOURCE_REF);
         xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

        resource = pcmk__find_constraint_resource(data_set->resources,
                                                  ID(xml_rsc));
        if (resource == NULL) {
            pcmk__config_err("%s: No resource found for %s",
                             set_id, ID(xml_rsc));
            return pcmk_rc_unpack_error;
        }

        unpack_rsc_location(location, resource, role, local_score, NULL);
    }

    return pcmk_rc_ok;
}

void
pcmk__unpack_location(xmlNode *xml_obj, pe_working_set_t *data_set)
{
    xmlNode *set = NULL;
    bool any_sets = false;

    xmlNode *orig_xml = NULL;
    xmlNode *expanded_xml = NULL;

    if (unpack_location_tags(xml_obj, &expanded_xml, data_set) != pcmk_rc_ok) {
        return;
    }

    if (expanded_xml) {
        orig_xml = xml_obj;
        xml_obj = expanded_xml;
    }

    for (set = first_named_child(xml_obj, XML_CONS_TAG_RSC_SET); set != NULL;
         set = crm_next_same_xml(set)) {

        any_sets = true;
        set = expand_idref(set, data_set->input);
        if ((set == NULL) // Configuration error, message already logged
            || (unpack_location_set(xml_obj, set, data_set) != pcmk_rc_ok)) {

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
        unpack_simple_location(xml_obj, data_set);
    }
}

/*!
 * \internal
 * \brief Add a new location constraint to a cluster working set
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
pe__location_t *
pcmk__new_location(const char *id, pe_resource_t *rsc,
                   int node_score, const char *discover_mode, pe_node_t *node)
{
    pe__location_t *new_con = NULL;

    if (id == NULL) {
        pe_err("Invalid constraint: no ID specified");
        return NULL;

    } else if (rsc == NULL) {
        pe_err("Invalid constraint %s: no resource specified", id);
        return NULL;

    } else if (node == NULL) {
        CRM_CHECK(node_score == 0, return NULL);
    }

    new_con = calloc(1, sizeof(pe__location_t));
    if (new_con != NULL) {
        new_con->id = strdup(id);
        new_con->rsc_lh = rsc;
        new_con->node_list_rh = NULL;
        new_con->role_filter = RSC_ROLE_UNKNOWN;

        if (pcmk__str_eq(discover_mode, "always",
                         pcmk__str_null_matches|pcmk__str_casei)) {
            new_con->discover_mode = pe_discover_always;

        } else if (pcmk__str_eq(discover_mode, "never", pcmk__str_casei)) {
            new_con->discover_mode = pe_discover_never;

        } else if (pcmk__str_eq(discover_mode, "exclusive", pcmk__str_casei)) {
            new_con->discover_mode = pe_discover_exclusive;
            rsc->exclusive_discover = TRUE;

        } else {
            pe_err("Invalid " XML_LOCATION_ATTR_DISCOVERY " value %s "
                   "in location constraint", discover_mode);
        }

        if (node != NULL) {
            pe_node_t *copy = pe__copy_node(node);

            copy->weight = node_score;
            new_con->node_list_rh = g_list_prepend(NULL, copy);
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
 * \param[in,out] data_set       Cluster working set
 */
void
pcmk__apply_locations(pe_working_set_t *data_set)
{
    for (GList *iter = data_set->placement_constraints;
         iter != NULL; iter = iter->next) {
        pe__location_t *location = iter->data;

        location->rsc_lh->cmds->apply_location(location->rsc_lh, location);
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
pcmk__apply_location(pe_resource_t *rsc, pe__location_t *location)
{
    bool need_role = false;

    CRM_ASSERT((rsc != NULL) && (location != NULL));

    // If a role was specified, ensure constraint is applicable
    need_role = (location->role_filter > RSC_ROLE_UNKNOWN);
    if (need_role && (location->role_filter != rsc->next_role)) {
        pe_rsc_trace(rsc,
                     "Not applying %s to %s because role will be %s not %s",
                     location->id, rsc->id, role2text(rsc->next_role),
                     role2text(location->role_filter));
        return;
    }

    if (location->node_list_rh == NULL) {
        pe_rsc_trace(rsc, "Not applying %s to %s because no nodes match",
                     location->id, rsc->id);
        return;
    }

    pe_rsc_trace(rsc, "Applying %s%s%s to %s", location->id,
                 (need_role? " for role " : ""),
                 (need_role? role2text(location->role_filter) : ""), rsc->id);

    for (GList *iter = location->node_list_rh;
         iter != NULL; iter = iter->next) {

        pe_node_t *node = iter->data;
        pe_node_t *allowed_node = NULL;

        allowed_node = (pe_node_t *) pe_hash_table_lookup(rsc->allowed_nodes,
                                                          node->details->id);
        if (allowed_node == NULL) {
            pe_rsc_trace(rsc, "* = %d on %s",
                         node->weight, pe__node_name(node));
            allowed_node = pe__copy_node(node);
            g_hash_table_insert(rsc->allowed_nodes,
                                (gpointer) allowed_node->details->id,
                                allowed_node);
        } else {
            pe_rsc_trace(rsc, "* + %d on %s",
                         node->weight, pe__node_name(node));
            allowed_node->weight = pcmk__add_scores(allowed_node->weight,
                                                    node->weight);
        }

        if (allowed_node->rsc_discover_mode < location->discover_mode) {
            if (location->discover_mode == pe_discover_exclusive) {
                rsc->exclusive_discover = TRUE;
            }
            /* exclusive > never > always... always is default */
            allowed_node->rsc_discover_mode = location->discover_mode;
        }
    }
}

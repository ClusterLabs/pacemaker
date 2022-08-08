/*
 * Copyright 2004-2022 the Pacemaker project contributors
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
        const char *attr_score = pe_node_attribute_calculated(node, score, rsc);

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

static pe__location_t *
generate_location_rule(pe_resource_t *rsc, xmlNode *rule_xml,
                       const char *discovery, crm_time_t *next_change,
                       pe_working_set_t *data_set,
                       pe_re_match_data_t *re_match_data)
{
    const char *rule_id = NULL;
    const char *score = NULL;
    const char *boolean = NULL;
    const char *role = NULL;

    GList *gIter = NULL;
    GList *match_L = NULL;

    bool do_and = true;
    bool accept = true;
    bool raw_score = true;
    bool score_allocated = false;

    pe__location_t *location_rule = NULL;

    rule_xml = expand_idref(rule_xml, data_set->input);
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

    location_rule = pcmk__new_location(rule_id, rsc, 0, discovery, NULL,
                                       data_set);

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
        GList *gIter = NULL;

        match_L = pcmk__copy_node_list(data_set->nodes, true);
        for (gIter = match_L; gIter != NULL; gIter = gIter->next) {
            pe_node_t *node = (pe_node_t *) gIter->data;

            node->weight = get_node_score(rule_id, score, raw_score, node, rsc);
        }
    }

    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        int score_f = 0;
        pe_node_t *node = (pe_node_t *) gIter->data;
        pe_match_data_t match_data = {
            .re = re_match_data,
            .params = pe_rsc_params(rsc, node, data_set),
            .meta = rsc->meta,
        };

        accept = pe_test_rule(rule_xml, node->details->attrs, RSC_ROLE_UNKNOWN,
                              data_set->now, next_change, &match_data);

        crm_trace("Rule %s %s on %s", ID(rule_xml), accept? "passed" : "failed",
                  node->details->uname);

        score_f = get_node_score(rule_id, score, raw_score, node, rsc);

        if (accept) {
            pe_node_t *local = pe_find_node_id(match_L, node->details->id);

            if ((local == NULL) && do_and) {
                continue;

            } else if (local == NULL) {
                local = pe__copy_node(node);
                match_L = g_list_append(match_L, local);
            }

            if (!do_and) {
                local->weight = pcmk__add_scores(local->weight, score_f);
            }
            crm_trace("node %s now has weight %d",
                      node->details->uname, local->weight);

        } else if (do_and && !accept) {
            // Remove it
            pe_node_t *delete = pe_find_node_id(match_L, node->details->id);

            if (delete != NULL) {
                match_L = g_list_remove(match_L, delete);
                crm_trace("node %s did not match", node->details->uname);
            }
            free(delete);
        }
    }

    if (score_allocated) {
        free((char *)score);
    }

    location_rule->node_list_rh = match_L;
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
                    const char *score, pe_working_set_t *data_set,
                    pe_re_match_data_t *re_match_data)
{
    pe__location_t *location = NULL;
    const char *rsc_id = crm_element_value(xml_obj, XML_LOC_ATTR_SOURCE);
    const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
    const char *node = crm_element_value(xml_obj, XML_CIB_TAG_NODE);
    const char *discovery = crm_element_value(xml_obj, XML_LOCATION_ATTR_DISCOVERY);

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
        pe_node_t *match = pe_find_node(data_set->nodes, node);

        if (!match) {
            return;
        }
        location = pcmk__new_location(id, rsc, score_i, discovery, match,
                                      data_set);

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
                                   data_set, re_match_data);
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

            pe__update_recheck_time(t, data_set);
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
            switch(r) {
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
        unpack_rsc_location(xml_obj, rsc, NULL, NULL, data_set, NULL);
    }

    value = crm_element_value(xml_obj, XML_LOC_ATTR_SOURCE_PATTERN);
    if (value) {
        regex_t *r_patt = calloc(1, sizeof(regex_t));
        bool invert = false;
        GList *rIter = NULL;

        if (value[0] == '!') {
            value++;
            invert = true;
        }

        if (regcomp(r_patt, value, REG_EXTENDED)) {
            pcmk__config_err("Ignoring constraint '%s' because "
                             XML_LOC_ATTR_SOURCE_PATTERN
                             " has invalid value '%s'", id, value);
            regfree(r_patt);
            free(r_patt);
            return;
        }

        for (rIter = data_set->resources; rIter; rIter = rIter->next) {
            pe_resource_t *r = rIter->data;
            int nregs = 0;
            regmatch_t *pmatch = NULL;
            int status;

            if(r_patt->re_nsub > 0) {
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
                unpack_rsc_location(xml_obj, r, NULL, NULL, data_set,
                                    &re_match_data);

            } else if (invert && (status != 0)) {
                crm_debug("'%s' is an inverted match of '%s' for %s",
                          r->id, value, id);
                unpack_rsc_location(xml_obj, r, NULL, NULL, data_set, NULL);

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

    CRM_CHECK(xml_obj != NULL, return pcmk_rc_schema_validation);

    id = ID(xml_obj);
    if (id == NULL) {
        pcmk__config_err("Ignoring <%s> constraint without " XML_ATTR_ID,
                         crm_element_name(xml_obj));
        return pcmk_rc_schema_validation;
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
        return pcmk_rc_schema_validation;

    } else if (rsc != NULL) {
        // No template is referenced
        return pcmk_rc_ok;
    }

    state = crm_element_value(xml_obj, XML_RULE_ATTR_ROLE);

    *expanded_xml = copy_xml(xml_obj);

    // Convert template/tag reference in "rsc" into resource_set under constraint
    if (!pcmk__tag_to_set(*expanded_xml, &rsc_set, XML_LOC_ATTR_SOURCE,
                          false, data_set)) {
        free_xml(*expanded_xml);
        *expanded_xml = NULL;
        return pcmk_rc_schema_validation;
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

    CRM_CHECK(set != NULL, return pcmk_rc_schema_validation);

    set_id = ID(set);
    if (set_id == NULL) {
        pcmk__config_err("Ignoring " XML_CONS_TAG_RSC_SET " without "
                         XML_ATTR_ID " in constraint '%s'",
                         pcmk__s(ID(location), "(missing ID)"));
        return pcmk_rc_schema_validation;
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
            return pcmk_rc_schema_validation;
        }

        unpack_rsc_location(location, resource, role, local_score, data_set,
                            NULL);
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
 * \param[in] id             XML ID of location constraint
 * \param[in] rsc            Resource in location constraint
 * \param[in] node_weight    Constraint score
 * \param[in] discover_mode  Resource discovery option for constraint
 * \param[in] node           Node in location constraint (or NULL if rule-based)
 * \param[in] data_set       Cluster working set to add constraint to
 *
 * \return Newly allocated location constraint
 * \note The result will be added to \p data_set and should not be freed
 *       separately.
 */
pe__location_t *
pcmk__new_location(const char *id, pe_resource_t *rsc,
                   int node_weight, const char *discover_mode,
                   pe_node_t *node, pe_working_set_t *data_set)
{
    pe__location_t *new_con = NULL;

    if (id == NULL) {
        pe_err("Invalid constraint: no ID specified");
        return NULL;

    } else if (rsc == NULL) {
        pe_err("Invalid constraint %s: no resource specified", id);
        return NULL;

    } else if (node == NULL) {
        CRM_CHECK(node_weight == 0, return NULL);
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

            copy->weight = node_weight;
            new_con->node_list_rh = g_list_prepend(NULL, copy);
        }

        data_set->placement_constraints = g_list_prepend(data_set->placement_constraints,
                                                         new_con);
        rsc->rsc_location = g_list_prepend(rsc->rsc_location, new_con);
    }

    return new_con;
}

/*!
 * \internal
 * \brief Apply all location constraints
 *
 * \param[in] data_set       Cluster working set
 */
void
pcmk__apply_locations(pe_working_set_t *data_set)
{
    for (GList *iter = data_set->placement_constraints;
         iter != NULL; iter = iter->next) {
        pe__location_t *location = iter->data;

        location->rsc_lh->cmds->rsc_location(location->rsc_lh, location);
    }
}

/*!
 * \internal
 * \brief Apply a location constraint to a resource's allowed node weights
 *
 * \param[in] constraint  Location constraint to apply
 * \param[in] rsc         Resource to apply constraint to
 */
void
pcmk__apply_location(pe__location_t *constraint, pe_resource_t *rsc)
{
    bool need_role = false;

    CRM_CHECK((constraint != NULL) && (rsc != NULL), return);

    // If a role was specified, ensure constraint is applicable
    need_role = (constraint->role_filter > RSC_ROLE_UNKNOWN);
    if (need_role && (constraint->role_filter != rsc->next_role)) {
        pe_rsc_trace(rsc,
                     "Not applying %s to %s because role will be %s not %s",
                     constraint->id, rsc->id, role2text(rsc->next_role),
                     role2text(constraint->role_filter));
        return;
    }

    if (constraint->node_list_rh == NULL) {
        pe_rsc_trace(rsc, "Not applying %s to %s because no nodes match",
                     constraint->id, rsc->id);
        return;
    }

    pe_rsc_trace(rsc, "Applying %s%s%s to %s", constraint->id,
                 (need_role? " for role " : ""),
                 (need_role? role2text(constraint->role_filter) : ""), rsc->id);

    for (GList *gIter = constraint->node_list_rh; gIter != NULL;
         gIter = gIter->next) {

        pe_node_t *node = (pe_node_t *) gIter->data;
        pe_node_t *weighted_node = NULL;

        weighted_node = (pe_node_t *) pe_hash_table_lookup(rsc->allowed_nodes,
                                                           node->details->id);
        if (weighted_node == NULL) {
            pe_rsc_trace(rsc, "* = %d on %s",
                         node->weight, node->details->uname);
            weighted_node = pe__copy_node(node);
            g_hash_table_insert(rsc->allowed_nodes,
                                (gpointer) weighted_node->details->id,
                                weighted_node);
        } else {
            pe_rsc_trace(rsc, "* + %d on %s",
                         node->weight, node->details->uname);
            weighted_node->weight = pcmk__add_scores(weighted_node->weight,
                                                     node->weight);
        }

        if (weighted_node->rsc_discover_mode < constraint->discover_mode) {
            if (constraint->discover_mode == pe_discover_exclusive) {
                rsc->exclusive_discover = TRUE;
            }
            /* exclusive > never > always... always is default */
            weighted_node->rsc_discover_mode = constraint->discover_mode;
        }
    }
}

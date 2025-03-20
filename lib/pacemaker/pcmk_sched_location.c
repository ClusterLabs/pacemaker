/*
 * Copyright 2004-2025 the Pacemaker project contributors
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
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

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
 * \brief Get the score attribute name (if any) used for a rule
 *
 * \param[in]  rule_xml    Rule XML
 * \param[out] allocated   If the score attribute name needs to be allocated,
 *                         this will be set to the non-const equivalent of the
 *                         return value (should be set to NULL when passed)
 * \param[in]  rule_input  Values used to evaluate rule criteria
 *
 * \return Score attribute name used for rule, or NULL if none
 * \note The caller is responsible for freeing \p *allocated if it is non-NULL.
 */
static const char *
score_attribute_name(const xmlNode *rule_xml, char **allocated,
                     const pcmk_rule_input_t *rule_input)
{
    const char *name = NULL;

    name = pcmk__xe_get(rule_xml, PCMK_XA_SCORE_ATTRIBUTE);
    if (name == NULL) {
        return NULL;
    }

    /* A score attribute name may use submatches extracted from a
     * resource ID regular expression. For example, if score-attribute is
     * "loc-\1", rsc-pattern is "ip-(.*)", and the resource ID is "ip-db", then
     * the score attribute name is "loc-db".
     */
    if ((rule_input->rsc_id != NULL) && (rule_input->rsc_id_nmatches > 0)) {
        *allocated = pcmk__replace_submatches(name, rule_input->rsc_id,
                                              rule_input->rsc_id_submatches,
                                              rule_input->rsc_id_nmatches);
        if (*allocated != NULL) {
            name = *allocated;
        }
    }
    return name;
}

/*!
 * \internal
 * \brief Parse a score from a rule without a score attribute
 *
 * \param[in]  rule_xml    Rule XML
 * \param[out] score       Where to store parsed score
 *
 * \return Standard Pacemaker return code
 */
static int
score_from_rule(const xmlNode *rule_xml, int *score)
{
    int rc = pcmk_rc_ok;
    const char *score_s = pcmk__xe_get(rule_xml, PCMK_XA_SCORE);

    if (score_s == NULL) { // Not possible with schema validation enabled
        pcmk__config_err("Ignoring location constraint rule %s because "
                         "neither " PCMK_XA_SCORE " nor "
                         PCMK_XA_SCORE_ATTRIBUTE " was specified",
                         pcmk__xe_id(rule_xml));
        return pcmk_rc_unpack_error;
    }

    rc = pcmk_parse_score(score_s, score, 0);
    if (rc != pcmk_rc_ok) { // Not possible with schema validation enabled
        pcmk__config_err("Ignoring location constraint rule %s because "
                         "'%s' is not a valid " PCMK_XA_SCORE ": %s",
                         pcmk__xe_id(rule_xml), score_s, pcmk_rc_str(rc));
        return pcmk_rc_unpack_error;
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Get a rule score from a node attribute
 *
 * \param[in]  constraint_id  Location constraint ID (for logging only)
 * \param[in]  attr_name      Name of node attribute with score
 * \param[in]  node           Node to get attribute for
 * \param[in]  rsc            Resource being located
 * \param[out] score          Where to store parsed score
 *
 * \return Standard Pacemaker return code (pcmk_rc_ok if a valid score was
 *         parsed, ENXIO if the node attribute was unset, and some other value
 *         if the node attribute value was invalid)
 */
static int
score_from_attr(const char *constraint_id, const char *attr_name,
                const pcmk_node_t *node, const pcmk_resource_t *rsc, int *score)
{
    int rc = pcmk_rc_ok;
    const char *target = NULL;
    const char *score_s = NULL;

    target = g_hash_table_lookup(rsc->priv->meta,
                                 PCMK_META_CONTAINER_ATTRIBUTE_TARGET);
    score_s = pcmk__node_attr(node, attr_name, target, pcmk__rsc_node_current);
    if (pcmk__str_empty(score_s)) {
        crm_info("Ignoring location %s for %s on %s "
                 "because it has no node attribute %s",
                 constraint_id, rsc->id, pcmk__node_name(node), attr_name);
        return ENXIO;
    }

    rc = pcmk_parse_score(score_s, score, 0);
    if (rc != pcmk_rc_ok) {
        crm_warn("Ignoring location %s for node %s because node "
                 "attribute %s value '%s' is not a valid score: %s",
                 constraint_id, pcmk__node_name(node), attr_name,
                 score_s, pcmk_rc_str(rc));
        return rc;
    }
    return pcmk_rc_ok;
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
 * \param[in,out] rule_input     Values used to evaluate rule criteria
 *                               (node-specific values will be overwritten by
 *                               this function)
 * \param[in]     constraint_id  ID of location constraint (for logging only)
 *
 * \return true if rule is valid, otherwise false
 */
static bool
generate_location_rule(pcmk_resource_t *rsc, xmlNode *rule_xml,
                       const char *discovery, crm_time_t *next_change,
                       pcmk_rule_input_t *rule_input, const char *constraint_id)
{
    const char *rule_id = NULL;
    const char *score_attr = NULL;
    const char *boolean = NULL;
    const char *role_spec = NULL;

    GList *iter = NULL;
    int score = 0;
    char *local_score_attr = NULL;
    pcmk__location_t *location_rule = NULL;
    enum rsc_role_e role = pcmk_role_unknown;
    enum pcmk__combine combine = pcmk__combine_unknown;

    rule_xml = pcmk__xe_resolve_idref(rule_xml, rsc->priv->scheduler->input);
    if (rule_xml == NULL) {
        return false; // Error already logged
    }

    rule_id = pcmk__xe_get(rule_xml, PCMK_XA_ID);
    if (rule_id == NULL) {
        pcmk__config_err("Ignoring location constraint '%s' because its rule "
                         "has no " PCMK_XA_ID,
                         constraint_id);
        return false;
    }

    boolean = pcmk__xe_get(rule_xml, PCMK_XA_BOOLEAN_OP);
    role_spec = pcmk__xe_get(rule_xml, PCMK_XA_ROLE);

    if (parse_location_role(role_spec, &role)) {
        crm_trace("Setting rule %s role filter to %s", rule_id, role_spec);
    } else {
        pcmk__config_err("Ignoring location constraint '%s' because rule '%s' "
                         "has invalid " PCMK_XA_ROLE " '%s'",
                         constraint_id, rule_id, role_spec);
        return false;
    }

    combine = pcmk__parse_combine(boolean);
    switch (combine) {
        case pcmk__combine_and:
        case pcmk__combine_or:
            break;

        default: // Not possible with schema validation enabled
            pcmk__config_err("Ignoring location constraint '%s' because rule "
                             "'%s' has invalid " PCMK_XA_BOOLEAN_OP " '%s'",
                             constraint_id, rule_id, boolean);
            return false;
    }

    /* Users may configure the rule with either a score or the name of a
     * node attribute whose value should be used as the constraint score for
     * that node.
     */
    score_attr = score_attribute_name(rule_xml, &local_score_attr, rule_input);
    if ((score_attr == NULL)
        && (score_from_rule(rule_xml, &score) != pcmk_rc_ok)) {
        return false;
    }

    location_rule = pcmk__new_location(rule_id, rsc, 0, discovery, NULL);
    CRM_CHECK(location_rule != NULL, return NULL);

    location_rule->role_filter = role;

    for (iter = rsc->priv->scheduler->nodes;
         iter != NULL; iter = iter->next) {

        pcmk_node_t *node = iter->data;
        pcmk_node_t *local = NULL;

        rule_input->node_attrs = node->priv->attrs;
        rule_input->rsc_params = pe_rsc_params(rsc, node,
                                               rsc->priv->scheduler);

        if (pcmk_evaluate_rule(rule_xml, rule_input,
                               next_change) != pcmk_rc_ok) {
            continue;
        }

        if ((score_attr != NULL)
            && (score_from_attr(constraint_id, score_attr, node, rsc,
                                &score) != pcmk_rc_ok)) {
            continue; // Message already logged
        }

        local = pe__copy_node(node);
        location_rule->nodes = g_list_prepend(location_rule->nodes, local);
        local->assign->score = score;
        pcmk__rsc_trace(rsc,
                        "Location %s score for %s on %s is %s via rule %s",
                        constraint_id, rsc->id, pcmk__node_name(node),
                        pcmk_readable_score(score), rule_id);
    }

    free(local_score_attr);

    if (location_rule->nodes == NULL) {
        crm_trace("No matching nodes for location constraint rule %s", rule_id);
    } else {
        crm_trace("Location constraint rule %s matched %d nodes",
                  rule_id, g_list_length(location_rule->nodes));
    }
    return true;
}

static void
unpack_rsc_location(xmlNode *xml_obj, pcmk_resource_t *rsc,
                    const char *role_spec, const char *score,
                    char *rsc_id_match, int rsc_id_nmatches,
                    regmatch_t *rsc_id_submatches)
{
    const char *rsc_id = pcmk__xe_get(xml_obj, PCMK_XA_RSC);
    const char *id = pcmk__xe_get(xml_obj, PCMK_XA_ID);
    const char *node = pcmk__xe_get(xml_obj, PCMK_XA_NODE);
    const char *discovery = pcmk__xe_get(xml_obj, PCMK_XA_RESOURCE_DISCOVERY);

    if (rsc == NULL) {
        pcmk__config_warn("Ignoring constraint '%s' because resource '%s' "
                          "does not exist", id, rsc_id);
        return;
    }

    if (score == NULL) {
        score = pcmk__xe_get(xml_obj, PCMK_XA_SCORE);
    }

    if ((node != NULL) && (score != NULL)) {
        int score_i = 0;
        int rc = pcmk_rc_ok;
        pcmk_node_t *match = pcmk_find_node(rsc->priv->scheduler, node);
        enum rsc_role_e role = pcmk_role_unknown;
        pcmk__location_t *location = NULL;

        if (match == NULL) {
            crm_info("Ignoring location constraint %s "
                     "because '%s' is not a known node",
                     pcmk__s(id, "without ID"), node);
            return;
        }

        rc = pcmk_parse_score(score, &score_i, 0);
        if (rc != pcmk_rc_ok) { // Not possible with schema validation enabled
            pcmk__config_err("Ignoring location constraint %s "
                             "because '%s' is not a valid score", id, score);
            return;
        }

        if (role_spec == NULL) {
            role_spec = pcmk__xe_get(xml_obj, PCMK_XA_ROLE);
        }
        if (parse_location_role(role_spec, &role)) {
            crm_trace("Setting location constraint %s role filter: %s",
                      id, role_spec);
        } else { // Not possible with schema validation enabled
            pcmk__config_err("Ignoring location constraint %s "
                             "because '%s' is not a valid " PCMK_XA_ROLE,
                             id, role_spec);
            return;
        }

        location = pcmk__new_location(id, rsc, score_i, discovery, match);
        if (location == NULL) {
            return; // Error already logged
        }
        location->role_filter = role;

    } else {
        crm_time_t *next_change = crm_time_new_undefined();
        xmlNode *rule_xml = pcmk__xe_first_child(xml_obj, PCMK_XE_RULE, NULL,
                                                 NULL);
        pcmk_rule_input_t rule_input = {
            .now = rsc->priv->scheduler->priv->now,
            .rsc_meta = rsc->priv->meta,
            .rsc_id = rsc_id_match,
            .rsc_id_submatches = rsc_id_submatches,
            .rsc_id_nmatches = rsc_id_nmatches,
        };

        generate_location_rule(rsc, rule_xml, discovery, next_change,
                               &rule_input, id);

        /* If there is a point in the future when the evaluation of a rule will
         * change, make sure the scheduler is re-run by that time.
         */
        if (crm_time_is_defined(next_change)) {
            time_t t = (time_t) crm_time_get_seconds_since_epoch(next_change);

            pcmk__update_recheck_time(t, rsc->priv->scheduler,
                                      "location rule evaluation");
        }
        crm_time_free(next_change);
    }
}

static void
unpack_simple_location(xmlNode *xml_obj, pcmk_scheduler_t *scheduler)
{
    const char *id = pcmk__xe_get(xml_obj, PCMK_XA_ID);
    const char *value = pcmk__xe_get(xml_obj, PCMK_XA_RSC);

    if (value) {
        pcmk_resource_t *rsc;

        rsc = pcmk__find_constraint_resource(scheduler->priv->resources, value);
        unpack_rsc_location(xml_obj, rsc, NULL, NULL, NULL, 0, NULL);
    }

    value = pcmk__xe_get(xml_obj, PCMK_XA_RSC_PATTERN);
    if (value) {
        regex_t regex;
        bool invert = false;

        if (value[0] == '!') {
            value++;
            invert = true;
        }

        if (regcomp(&regex, value, REG_EXTENDED) != 0) {
            pcmk__config_err("Ignoring constraint '%s' because "
                             PCMK_XA_RSC_PATTERN
                             " has invalid value '%s'", id, value);
            return;
        }

        for (GList *iter = scheduler->priv->resources;
             iter != NULL; iter = iter->next) {

            pcmk_resource_t *r = iter->data;
            int nregs = 0;
            regmatch_t *pmatch = NULL;
            int status;

            if (regex.re_nsub > 0) {
                nregs = regex.re_nsub + 1;
            } else {
                nregs = 1;
            }
            pmatch = pcmk__assert_alloc(nregs, sizeof(regmatch_t));

            status = regexec(&regex, r->id, nregs, pmatch, 0);

            if (!invert && (status == 0)) {
                crm_debug("'%s' matched '%s' for %s", r->id, value, id);
                unpack_rsc_location(xml_obj, r, NULL, NULL, r->id, nregs,
                                    pmatch);

            } else if (invert && (status != 0)) {
                crm_debug("'%s' is an inverted match of '%s' for %s",
                          r->id, value, id);
                unpack_rsc_location(xml_obj, r, NULL, NULL, NULL, 0, NULL);

            } else {
                crm_trace("'%s' does not match '%s' for %s", r->id, value, id);
            }

            free(pmatch);
        }

        // @TODO Maybe log a notice if we did not match any resources

        regfree(&regex);
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
    pcmk__idref_t *tag = NULL;
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

    rsc_id = pcmk__xe_get(xml_obj, PCMK_XA_RSC);
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

    state = pcmk__xe_get(xml_obj, PCMK_XA_ROLE);

    *expanded_xml = pcmk__xml_copy(NULL, xml_obj);

    /* Convert any template or tag reference into constraint
     * PCMK_XE_RESOURCE_SET
     */
    if (!pcmk__tag_to_set(*expanded_xml, &rsc_set, PCMK_XA_RSC,
                          false, scheduler)) {
        pcmk__xml_free(*expanded_xml);
        *expanded_xml = NULL;
        return pcmk_rc_unpack_error;
    }

    if (rsc_set != NULL) {
        if (state != NULL) {
            /* Move PCMK_XA_RSC_ROLE into converted PCMK_XE_RESOURCE_SET as
             * PCMK_XA_ROLE attribute
             */
            pcmk__xe_set(rsc_set, PCMK_XA_ROLE, state);
            pcmk__xe_remove_attr(*expanded_xml, PCMK_XA_ROLE);
        }
        crm_log_xml_trace(*expanded_xml, "Expanded " PCMK_XE_RSC_LOCATION);

    } else {
        // No sets
        pcmk__xml_free(*expanded_xml);
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

    role = pcmk__xe_get(set, PCMK_XA_ROLE);
    local_score = pcmk__xe_get(set, PCMK_XA_SCORE);

    for (xml_rsc = pcmk__xe_first_child(set, PCMK_XE_RESOURCE_REF, NULL, NULL);
         xml_rsc != NULL;
         xml_rsc = pcmk__xe_next(xml_rsc, PCMK_XE_RESOURCE_REF)) {

        resource = pcmk__find_constraint_resource(scheduler->priv->resources,
                                                  pcmk__xe_id(xml_rsc));
        if (resource == NULL) {
            pcmk__config_err("%s: No resource found for %s",
                             set_id, pcmk__xe_id(xml_rsc));
            return pcmk_rc_unpack_error;
        }

        unpack_rsc_location(location, resource, role, local_score, NULL, 0,
                            NULL);
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
         set != NULL; set = pcmk__xe_next(set, PCMK_XE_RESOURCE_SET)) {

        any_sets = true;
        set = pcmk__xe_resolve_idref(set, scheduler->input);
        if ((set == NULL) // Configuration error, message already logged
            || (unpack_location_set(xml_obj, set, scheduler) != pcmk_rc_ok)) {

            if (expanded_xml) {
                pcmk__xml_free(expanded_xml);
            }
            return;
        }
    }

    if (expanded_xml) {
        pcmk__xml_free(expanded_xml);
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
 * \param[in]     probe_mode     When resource should be probed on node
 * \param[in]     node           Node in constraint (or NULL if rule-based)
 *
 * \return Newly allocated location constraint on success, otherwise NULL
 * \note The result will be added to the cluster (via \p rsc) and should not be
 *       freed separately.
 */
pcmk__location_t *
pcmk__new_location(const char *id, pcmk_resource_t *rsc,
                   int node_score, const char *probe_mode, pcmk_node_t *node)
{
    pcmk__location_t *new_con = NULL;

    CRM_CHECK((node != NULL) || (node_score == 0), return NULL);

    if (id == NULL) {
        pcmk__config_err("Invalid constraint: no ID specified");
        return NULL;
    }

    if (rsc == NULL) {
        pcmk__config_err("Invalid constraint %s: no resource specified", id);
        return NULL;
    }

    new_con = pcmk__assert_alloc(1, sizeof(pcmk__location_t));
    new_con->id = pcmk__str_copy(id);
    new_con->rsc = rsc;
    new_con->nodes = NULL;
    new_con->role_filter = pcmk_role_unknown;

    if (pcmk__str_eq(probe_mode, PCMK_VALUE_ALWAYS,
                     pcmk__str_null_matches|pcmk__str_casei)) {
        new_con->probe_mode = pcmk__probe_always;

    } else if (pcmk__str_eq(probe_mode, PCMK_VALUE_NEVER, pcmk__str_casei)) {
        new_con->probe_mode = pcmk__probe_never;

    } else if (pcmk__str_eq(probe_mode, PCMK_VALUE_EXCLUSIVE,
                            pcmk__str_casei)) {
        new_con->probe_mode = pcmk__probe_exclusive;
        pcmk__set_rsc_flags(rsc, pcmk__rsc_exclusive_probes);

    } else {
        pcmk__config_err("Invalid " PCMK_XA_RESOURCE_DISCOVERY " value %s "
                         "in location constraint", probe_mode);
    }

    if (node != NULL) {
        pcmk_node_t *copy = pe__copy_node(node);

        copy->assign->score = node_score;
        new_con->nodes = g_list_prepend(NULL, copy);
    }

    rsc->priv->scheduler->priv->location_constraints =
        g_list_prepend(rsc->priv->scheduler->priv->location_constraints,
                       new_con);
    rsc->priv->location_constraints =
        g_list_prepend(rsc->priv->location_constraints, new_con);

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
    for (GList *iter = scheduler->priv->location_constraints;
         iter != NULL; iter = iter->next) {
        pcmk__location_t *location = iter->data;

        location->rsc->priv->cmds->apply_location(location->rsc, location);
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

    pcmk__assert((rsc != NULL) && (location != NULL));

    // If a role was specified, ensure constraint is applicable
    need_role = (location->role_filter > pcmk_role_unknown);
    if (need_role && (location->role_filter != rsc->priv->next_role)) {
        pcmk__rsc_trace(rsc,
                        "Not applying %s to %s because role will be %s not %s",
                        location->id, rsc->id,
                        pcmk_role_text(rsc->priv->next_role),
                        pcmk_role_text(location->role_filter));
        return;
    }

    if (location->nodes == NULL) {
        pcmk__rsc_trace(rsc, "Not applying %s to %s because no nodes match",
                        location->id, rsc->id);
        return;
    }

    for (GList *iter = location->nodes; iter != NULL; iter = iter->next) {
        pcmk_node_t *node = iter->data;
        pcmk_node_t *allowed_node = NULL;

        allowed_node = g_hash_table_lookup(rsc->priv->allowed_nodes,
                                           node->priv->id);

        pcmk__rsc_trace(rsc, "Applying %s%s%s to %s score on %s: %c %s",
                        location->id,
                        (need_role? " for role " : ""),
                        (need_role? pcmk_role_text(location->role_filter) : ""),
                        rsc->id, pcmk__node_name(node),
                        ((allowed_node == NULL)? '=' : '+'),
                        pcmk_readable_score(node->assign->score));

        if (allowed_node == NULL) {
            allowed_node = pe__copy_node(node);
            g_hash_table_insert(rsc->priv->allowed_nodes,
                                (gpointer) allowed_node->priv->id,
                                allowed_node);
        } else {
            allowed_node->assign->score =
                pcmk__add_scores(allowed_node->assign->score,
                                 node->assign->score);
        }

        if (allowed_node->assign->probe_mode < location->probe_mode) {
            if (location->probe_mode == pcmk__probe_exclusive) {
                pcmk__set_rsc_flags(rsc, pcmk__rsc_exclusive_probes);
            }
            /* exclusive > never > always... always is default */
            allowed_node->assign->probe_mode = location->probe_mode;
        }
    }
}

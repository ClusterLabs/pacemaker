/*
 * Copyright 2004-2021 the Pacemaker project contributors
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

#define EXPAND_CONSTRAINT_IDREF(__set, __rsc, __name) do {                      \
        __rsc = pcmk__find_constraint_resource(data_set->resources, __name);    \
        if (__rsc == NULL) {                                                    \
            pcmk__config_err("%s: No resource found for %s", __set, __name);    \
            return;                                                             \
        }                                                                       \
    } while(0)

static gint
sort_cons_priority_lh(gconstpointer a, gconstpointer b)
{
    const pcmk__colocation_t *rsc_constraint1 = (const pcmk__colocation_t *) a;
    const pcmk__colocation_t *rsc_constraint2 = (const pcmk__colocation_t *) b;

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

    /* Process clones before primitives and groups */
    if (rsc_constraint1->rsc_lh->variant > rsc_constraint2->rsc_lh->variant) {
        return -1;
    } else if (rsc_constraint1->rsc_lh->variant < rsc_constraint2->rsc_lh->variant) {
        return 1;
    }

    /* @COMPAT scheduler <2.0.0: Process promotable clones before nonpromotable
     * clones (probably unnecessary, but avoids having to update regression
     * tests)
     */
    if (rsc_constraint1->rsc_lh->variant == pe_clone) {
        if (pcmk_is_set(rsc_constraint1->rsc_lh->flags, pe_rsc_promotable)
            && !pcmk_is_set(rsc_constraint2->rsc_lh->flags, pe_rsc_promotable)) {
            return -1;
        } else if (!pcmk_is_set(rsc_constraint1->rsc_lh->flags, pe_rsc_promotable)
            && pcmk_is_set(rsc_constraint2->rsc_lh->flags, pe_rsc_promotable)) {
            return 1;
        }
    }

    return strcmp(rsc_constraint1->rsc_lh->id, rsc_constraint2->rsc_lh->id);
}

static gint
sort_cons_priority_rh(gconstpointer a, gconstpointer b)
{
    const pcmk__colocation_t *rsc_constraint1 = (const pcmk__colocation_t *) a;
    const pcmk__colocation_t *rsc_constraint2 = (const pcmk__colocation_t *) b;

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

    /* Process clones before primitives and groups */
    if (rsc_constraint1->rsc_rh->variant > rsc_constraint2->rsc_rh->variant) {
        return -1;
    } else if (rsc_constraint1->rsc_rh->variant < rsc_constraint2->rsc_rh->variant) {
        return 1;
    }

    /* @COMPAT scheduler <2.0.0: Process promotable clones before nonpromotable
     * clones (probably unnecessary, but avoids having to update regression
     * tests)
     */
    if (rsc_constraint1->rsc_rh->variant == pe_clone) {
        if (pcmk_is_set(rsc_constraint1->rsc_rh->flags, pe_rsc_promotable)
            && !pcmk_is_set(rsc_constraint2->rsc_rh->flags, pe_rsc_promotable)) {
            return -1;
        } else if (!pcmk_is_set(rsc_constraint1->rsc_rh->flags, pe_rsc_promotable)
            && pcmk_is_set(rsc_constraint2->rsc_rh->flags, pe_rsc_promotable)) {
            return 1;
        }
    }

    return strcmp(rsc_constraint1->rsc_rh->id, rsc_constraint2->rsc_rh->id);
}

/*!
 * \internal
 * \brief Add orderings necessary for an anti-colocation constraint
 */
static void
anti_colocation_order(pe_resource_t *first_rsc, int first_role,
                      pe_resource_t *then_rsc, int then_role,
                      pe_working_set_t *data_set)
{
    const char *first_tasks[] = { NULL, NULL };
    const char *then_tasks[] = { NULL, NULL };

    /* Actions to make first_rsc lose first_role */
    if (first_role == RSC_ROLE_PROMOTED) {
        first_tasks[0] = CRMD_ACTION_DEMOTE;

    } else {
        first_tasks[0] = CRMD_ACTION_STOP;

        if (first_role == RSC_ROLE_UNPROMOTED) {
            first_tasks[1] = CRMD_ACTION_PROMOTE;
        }
    }

    /* Actions to make then_rsc gain then_role */
    if (then_role == RSC_ROLE_PROMOTED) {
        then_tasks[0] = CRMD_ACTION_PROMOTE;

    } else {
        then_tasks[0] = CRMD_ACTION_START;

        if (then_role == RSC_ROLE_UNPROMOTED) {
            then_tasks[1] = CRMD_ACTION_DEMOTE;
        }
    }

    for (int first_lpc = 0;
         (first_lpc <= 1) && (first_tasks[first_lpc] != NULL); first_lpc++) {

        for (int then_lpc = 0;
             (then_lpc <= 1) && (then_tasks[then_lpc] != NULL); then_lpc++) {

            pcmk__order_resource_actions(first_rsc, first_tasks[first_lpc],
                                         then_rsc, then_tasks[then_lpc],
                                         pe_order_anti_colocation, data_set);
        }
    }
}

/*!
 * \internal
 * \brief Add a new colocation constraint to a cluster working set
 *
 * \param[in] id         XML ID for this constraint
 * \param[in] node_attr  Colocate by this attribute (or NULL for #uname)
 * \param[in] score      Constraint score
 * \param[in] rsc_lh     Resource to be colocated
 * \param[in] rsc_rh     Resource to colocate \p rsc_lh with
 * \param[in] state_lh   Current role of \p rsc_lh
 * \param[in] state_rh   Current role of \p rsc_rh
 * \param[in] influence  Whether colocation constraint has influence
 * \param[in] data_set   Cluster working set to add constraint to
 */
void
pcmk__new_colocation(const char *id, const char *node_attr, int score,
                     pe_resource_t *rsc_lh, pe_resource_t *rsc_rh,
                     const char *state_lh, const char *state_rh,
                     bool influence, pe_working_set_t *data_set)
{
    pcmk__colocation_t *new_con = NULL;

    if (score == 0) {
        crm_trace("Ignoring colocation '%s' because score is 0", id);
        return;
    }
    if ((rsc_lh == NULL) || (rsc_rh == NULL)) {
        pcmk__config_err("Ignoring colocation '%s' because resource "
                         "does not exist", id);
        return;
    }

    new_con = calloc(1, sizeof(pcmk__colocation_t));
    if (new_con == NULL) {
        return;
    }

    if (pcmk__str_eq(state_lh, RSC_ROLE_STARTED_S,
                     pcmk__str_null_matches|pcmk__str_casei)) {
        state_lh = RSC_ROLE_UNKNOWN_S;
    }

    if (pcmk__str_eq(state_rh, RSC_ROLE_STARTED_S,
                     pcmk__str_null_matches|pcmk__str_casei)) {
        state_rh = RSC_ROLE_UNKNOWN_S;
    }

    new_con->id = id;
    new_con->rsc_lh = rsc_lh;
    new_con->rsc_rh = rsc_rh;
    new_con->score = score;
    new_con->role_lh = text2role(state_lh);
    new_con->role_rh = text2role(state_rh);
    new_con->node_attribute = node_attr;
    new_con->influence = influence;

    if (node_attr == NULL) {
        node_attr = CRM_ATTR_UNAME;
    }

    pe_rsc_trace(rsc_lh, "%s ==> %s (%s %d)",
                 rsc_lh->id, rsc_rh->id, node_attr, score);

    rsc_lh->rsc_cons = g_list_insert_sorted(rsc_lh->rsc_cons, new_con,
                                            sort_cons_priority_rh);

    rsc_rh->rsc_cons_lhs = g_list_insert_sorted(rsc_rh->rsc_cons_lhs, new_con,
                                                sort_cons_priority_lh);

    data_set->colocation_constraints = g_list_append(data_set->colocation_constraints,
                                                     new_con);

    if (score <= -INFINITY) {
        anti_colocation_order(rsc_lh, new_con->role_lh, rsc_rh,
                              new_con->role_rh, data_set);
        anti_colocation_order(rsc_rh, new_con->role_rh, rsc_lh,
                              new_con->role_lh, data_set);
    }
}

/*!
 * \internal
 * \brief Return the boolean influence corresponding to configuration
 *
 * \param[in] coloc_id     Colocation XML ID (for error logging)
 * \param[in] rsc          Resource involved in constraint (for default)
 * \param[in] influence_s  String value of influence option
 *
 * \return true if string evaluates true, false if string evaluates false,
 *         or value of resource's critical option if string is NULL or invalid
 */
static bool
unpack_influence(const char *coloc_id, const pe_resource_t *rsc,
                 const char *influence_s)
{
    if (influence_s != NULL) {
        int influence_i = 0;

        if (crm_str_to_boolean(influence_s, &influence_i) < 0) {
            pcmk__config_err("Constraint '%s' has invalid value for "
                             XML_COLOC_ATTR_INFLUENCE " (using default)",
                             coloc_id);
        } else {
            return (influence_i != 0);
        }
    }
    return pcmk_is_set(rsc->flags, pe_rsc_critical);
}

static void
unpack_colocation_set(xmlNode *set, int score, const char *coloc_id,
                      const char *influence_s, pe_working_set_t *data_set)
{
    xmlNode *xml_rsc = NULL;
    pe_resource_t *with = NULL;
    pe_resource_t *resource = NULL;
    const char *set_id = ID(set);
    const char *role = crm_element_value(set, "role");
    const char *sequential = crm_element_value(set, "sequential");
    const char *ordering = crm_element_value(set, "ordering");
    int local_score = score;

    const char *score_s = crm_element_value(set, XML_RULE_ATTR_SCORE);

    if (score_s) {
        local_score = char2score(score_s);
    }
    if (local_score == 0) {
        crm_trace("Ignoring colocation '%s' for set '%s' because score is 0",
                  coloc_id, set_id);
        return;
    }

    if (ordering == NULL) {
        ordering = "group";
    }

    if ((sequential != NULL) && !crm_is_true(sequential)) {
        return;

    } else if ((local_score > 0)
               && pcmk__str_eq(ordering, "group", pcmk__str_casei)) {
        for (xml_rsc = first_named_child(set, XML_TAG_RESOURCE_REF);
             xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

            EXPAND_CONSTRAINT_IDREF(set_id, resource, ID(xml_rsc));
            if (with != NULL) {
                pe_rsc_trace(resource, "Colocating %s with %s", resource->id, with->id);
                pcmk__new_colocation(set_id, NULL, local_score, resource,
                                     with, role, role,
                                     unpack_influence(coloc_id, resource,
                                                      influence_s), data_set);
            }
            with = resource;
        }

    } else if (local_score > 0) {
        pe_resource_t *last = NULL;

        for (xml_rsc = first_named_child(set, XML_TAG_RESOURCE_REF);
             xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

            EXPAND_CONSTRAINT_IDREF(set_id, resource, ID(xml_rsc));
            if (last != NULL) {
                pe_rsc_trace(resource, "Colocating %s with %s",
                             last->id, resource->id);
                pcmk__new_colocation(set_id, NULL, local_score, last,
                                     resource, role, role,
                                     unpack_influence(coloc_id, last,
                                                      influence_s), data_set);
            }

            last = resource;
        }

    } else {
        /* Anti-colocating with every prior resource is
         * the only way to ensure the intuitive result
         * (i.e. that no one in the set can run with anyone else in the set)
         */

        for (xml_rsc = first_named_child(set, XML_TAG_RESOURCE_REF);
             xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

            xmlNode *xml_rsc_with = NULL;
            bool influence = true;

            EXPAND_CONSTRAINT_IDREF(set_id, resource, ID(xml_rsc));
            influence = unpack_influence(coloc_id, resource, influence_s);

            for (xml_rsc_with = first_named_child(set, XML_TAG_RESOURCE_REF);
                 xml_rsc_with != NULL;
                 xml_rsc_with = crm_next_same_xml(xml_rsc_with)) {

                if (pcmk__str_eq(resource->id, ID(xml_rsc_with),
                                 pcmk__str_casei)) {
                    break;
                }
                EXPAND_CONSTRAINT_IDREF(set_id, with, ID(xml_rsc_with));
                pe_rsc_trace(resource, "Anti-Colocating %s with %s", resource->id,
                             with->id);
                pcmk__new_colocation(set_id, NULL, local_score,
                                     resource, with, role, role,
                                     influence, data_set);
            }
        }
    }
}

static void
colocate_rsc_sets(const char *id, xmlNode *set1, xmlNode *set2, int score,
                  const char *influence_s, pe_working_set_t *data_set)
{
    xmlNode *xml_rsc = NULL;
    pe_resource_t *rsc_1 = NULL;
    pe_resource_t *rsc_2 = NULL;

    const char *role_1 = crm_element_value(set1, "role");
    const char *role_2 = crm_element_value(set2, "role");

    const char *sequential_1 = crm_element_value(set1, "sequential");
    const char *sequential_2 = crm_element_value(set2, "sequential");

    if (score == 0) {
        crm_trace("Ignoring colocation '%s' between sets because score is 0",
                  id);
        return;
    }
    if ((sequential_1 == NULL) || crm_is_true(sequential_1)) {
        // Get the first one
        xml_rsc = first_named_child(set1, XML_TAG_RESOURCE_REF);
        if (xml_rsc != NULL) {
            EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));
        }
    }

    if ((sequential_2 == NULL) || crm_is_true(sequential_2)) {
        // Get the last one
        const char *rid = NULL;

        for (xml_rsc = first_named_child(set2, XML_TAG_RESOURCE_REF);
             xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

            rid = ID(xml_rsc);
        }
        EXPAND_CONSTRAINT_IDREF(id, rsc_2, rid);
    }

    if ((rsc_1 != NULL) && (rsc_2 != NULL)) {
        pcmk__new_colocation(id, NULL, score, rsc_1, rsc_2, role_1, role_2,
                             unpack_influence(id, rsc_1, influence_s),
                             data_set);

    } else if (rsc_1 != NULL) {
        bool influence = unpack_influence(id, rsc_1, influence_s);

        for (xml_rsc = first_named_child(set2, XML_TAG_RESOURCE_REF);
             xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

            EXPAND_CONSTRAINT_IDREF(id, rsc_2, ID(xml_rsc));
            pcmk__new_colocation(id, NULL, score, rsc_1, rsc_2, role_1,
                                 role_2, influence, data_set);
        }

    } else if (rsc_2 != NULL) {
        for (xml_rsc = first_named_child(set1, XML_TAG_RESOURCE_REF);
             xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

            EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));
            pcmk__new_colocation(id, NULL, score, rsc_1, rsc_2, role_1,
                                 role_2,
                                 unpack_influence(id, rsc_1, influence_s),
                                 data_set);
        }

    } else {
        for (xml_rsc = first_named_child(set1, XML_TAG_RESOURCE_REF);
             xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

            xmlNode *xml_rsc_2 = NULL;
            bool influence = true;

            EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));
            influence = unpack_influence(id, rsc_1, influence_s);

            for (xml_rsc_2 = first_named_child(set2, XML_TAG_RESOURCE_REF);
                 xml_rsc_2 != NULL;
                 xml_rsc_2 = crm_next_same_xml(xml_rsc_2)) {

                EXPAND_CONSTRAINT_IDREF(id, rsc_2, ID(xml_rsc_2));
                pcmk__new_colocation(id, NULL, score, rsc_1, rsc_2,
                                     role_1, role_2, influence,
                                     data_set);
            }
        }
    }
}

static void
unpack_simple_colocation(xmlNode *xml_obj, const char *id,
                         const char *influence_s, pe_working_set_t *data_set)
{
    int score_i = 0;

    const char *score = crm_element_value(xml_obj, XML_RULE_ATTR_SCORE);
    const char *id_lh = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE);
    const char *id_rh = crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET);
    const char *state_lh = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE_ROLE);
    const char *state_rh = crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET_ROLE);
    const char *attr = crm_element_value(xml_obj, XML_COLOC_ATTR_NODE_ATTR);
    const char *symmetrical = crm_element_value(xml_obj, XML_CONS_ATTR_SYMMETRICAL);

    // experimental syntax from pacemaker-next (unlikely to be adopted as-is)
    const char *instance_lh = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE_INSTANCE);
    const char *instance_rh = crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET_INSTANCE);

    pe_resource_t *rsc_lh = pcmk__find_constraint_resource(data_set->resources, id_lh);
    pe_resource_t *rsc_rh = pcmk__find_constraint_resource(data_set->resources, id_rh);

    if (rsc_lh == NULL) {
        pcmk__config_err("Ignoring constraint '%s' because resource '%s' "
                         "does not exist", id, id_lh);
        return;

    } else if (rsc_rh == NULL) {
        pcmk__config_err("Ignoring constraint '%s' because resource '%s' "
                         "does not exist", id, id_rh);
        return;

    } else if ((instance_lh != NULL) && !pe_rsc_is_clone(rsc_lh)) {
        pcmk__config_err("Ignoring constraint '%s' because resource '%s' "
                         "is not a clone but instance '%s' was requested",
                         id, id_lh, instance_lh);
        return;

    } else if ((instance_rh != NULL) && !pe_rsc_is_clone(rsc_rh)) {
        pcmk__config_err("Ignoring constraint '%s' because resource '%s' "
                         "is not a clone but instance '%s' was requested",
                         id, id_rh, instance_rh);
        return;
    }

    if (instance_lh != NULL) {
        rsc_lh = find_clone_instance(rsc_lh, instance_lh, data_set);
        if (rsc_lh == NULL) {
            pcmk__config_warn("Ignoring constraint '%s' because resource '%s' "
                              "does not have an instance '%s'",
                              id, id_lh, instance_lh);
            return;
        }
    }

    if (instance_rh != NULL) {
        rsc_rh = find_clone_instance(rsc_rh, instance_rh, data_set);
        if (rsc_rh == NULL) {
            pcmk__config_warn("Ignoring constraint '%s' because resource '%s' "
                              "does not have an instance '%s'",
                              "'%s'", id, id_rh, instance_rh);
            return;
        }
    }

    if (crm_is_true(symmetrical)) {
        pcmk__config_warn("The colocation constraint '"
                          XML_CONS_ATTR_SYMMETRICAL
                          "' attribute has been removed");
    }

    if (score) {
        score_i = char2score(score);
    }

    pcmk__new_colocation(id, attr, score_i, rsc_lh, rsc_rh, state_lh, state_rh,
                         unpack_influence(id, rsc_lh, influence_s), data_set);
}

// \return Standard Pacemaker return code
static int
unpack_colocation_tags(xmlNode *xml_obj, xmlNode **expanded_xml,
                       pe_working_set_t *data_set)
{
    const char *id = NULL;
    const char *id_lh = NULL;
    const char *id_rh = NULL;
    const char *state_lh = NULL;
    const char *state_rh = NULL;

    pe_resource_t *rsc_lh = NULL;
    pe_resource_t *rsc_rh = NULL;

    pe_tag_t *tag_lh = NULL;
    pe_tag_t *tag_rh = NULL;

    xmlNode *rsc_set_lh = NULL;
    xmlNode *rsc_set_rh = NULL;
    bool any_sets = false;

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
        crm_log_xml_trace(*expanded_xml, "Expanded rsc_colocation");
        return pcmk_rc_ok;
    }

    id_lh = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE);
    id_rh = crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET);
    if (id_lh == NULL || id_rh == NULL) {
        return pcmk_rc_ok;
    }

    if (!pcmk__valid_resource_or_tag(data_set, id_lh, &rsc_lh, &tag_lh)) {
        pcmk__config_err("Ignoring constraint '%s' because '%s' is not a "
                         "valid resource or tag", id, id_lh);
        return pcmk_rc_schema_validation;
    }

    if (!pcmk__valid_resource_or_tag(data_set, id_rh, &rsc_rh, &tag_rh)) {
        pcmk__config_err("Ignoring constraint '%s' because '%s' is not a "
                         "valid resource or tag", id, id_rh);
        return pcmk_rc_schema_validation;
    }

    if (rsc_lh && rsc_rh) {
        /* Neither side references any template/tag. */
        return pcmk_rc_ok;
    }

    if (tag_lh && tag_rh) {
        // A colocation constraint between two templates/tags makes no sense
        pcmk__config_err("Ignoring constraint '%s' because two templates or "
                         "tags cannot be colocated", id);
        return pcmk_rc_schema_validation;
    }

    state_lh = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE_ROLE);
    state_rh = crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET_ROLE);

    *expanded_xml = copy_xml(xml_obj);

    // Convert template/tag reference in "rsc" into resource_set under constraint
    if (!pcmk__tag_to_set(*expanded_xml, &rsc_set_lh, XML_COLOC_ATTR_SOURCE,
                          TRUE, data_set)) {
        free_xml(*expanded_xml);
        *expanded_xml = NULL;
        return pcmk_rc_schema_validation;
    }

    if (rsc_set_lh != NULL) {
        if (state_lh != NULL) {
            // Move "rsc-role" into converted resource_set as "role"
            crm_xml_add(rsc_set_lh, "role", state_lh);
            xml_remove_prop(*expanded_xml, XML_COLOC_ATTR_SOURCE_ROLE);
        }
        any_sets = true;
    }

    // Convert template/tag reference in "with-rsc" into resource_set under constraint
    if (!pcmk__tag_to_set(*expanded_xml, &rsc_set_rh, XML_COLOC_ATTR_TARGET,
                          TRUE, data_set)) {
        free_xml(*expanded_xml);
        *expanded_xml = NULL;
        return pcmk_rc_schema_validation;
    }

    if (rsc_set_rh != NULL) {
        if (state_rh != NULL) {
            // Move "with-rsc-role" into converted resource_set as "role"
            crm_xml_add(rsc_set_rh, "role", state_rh);
            xml_remove_prop(*expanded_xml, XML_COLOC_ATTR_TARGET_ROLE);
        }
        any_sets = true;
    }

    if (any_sets) {
        crm_log_xml_trace(*expanded_xml, "Expanded rsc_colocation");
    } else {
        free_xml(*expanded_xml);
        *expanded_xml = NULL;
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Parse a colocation constraint from XML into a cluster working set
 *
 * \param[in] xml_obj   Colocation constraint XML to unpack
 * \param[in] data_set  Cluster working set to add constraint to
 */
void
pcmk__unpack_colocation(xmlNode *xml_obj, pe_working_set_t *data_set)
{
    int score_i = 0;
    xmlNode *set = NULL;
    xmlNode *last = NULL;

    xmlNode *orig_xml = NULL;
    xmlNode *expanded_xml = NULL;

    const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
    const char *score = crm_element_value(xml_obj, XML_RULE_ATTR_SCORE);
    const char *influence_s = crm_element_value(xml_obj,
                                                XML_COLOC_ATTR_INFLUENCE);

    if (score) {
        score_i = char2score(score);
    }

    if (unpack_colocation_tags(xml_obj, &expanded_xml,
                               data_set) != pcmk_rc_ok) {
        return;
    }
    if (expanded_xml) {
        orig_xml = xml_obj;
        xml_obj = expanded_xml;
    }

    for (set = first_named_child(xml_obj, XML_CONS_TAG_RSC_SET); set != NULL;
         set = crm_next_same_xml(set)) {

        set = expand_idref(set, data_set->input);
        if (set == NULL) { // Configuration error, message already logged
            if (expanded_xml != NULL) {
                free_xml(expanded_xml);
            }
            return;
        }

        unpack_colocation_set(set, score_i, id, influence_s, data_set);

        if (last != NULL) {
            colocate_rsc_sets(id, last, set, score_i, influence_s, data_set);
        }
        last = set;
    }

    if (expanded_xml) {
        free_xml(expanded_xml);
        xml_obj = orig_xml;
    }

    if (last == NULL) {
        unpack_simple_colocation(xml_obj, id, influence_s, data_set);
    }
}

static void
mark_start_blocked(pe_resource_t *rsc, pe_resource_t *reason,
                   pe_working_set_t *data_set)
{
    char *reason_text = crm_strdup_printf("colocation with %s", reason->id);

    for (GList *gIter = rsc->actions; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

        if (pcmk_is_set(action->flags, pe_action_runnable)
            && pcmk__str_eq(action->task, RSC_START, pcmk__str_casei)) {

            pe__clear_action_flags(action, pe_action_runnable);
            pe_action_set_reason(action, reason_text, false);
            pcmk__block_colocated_starts(action, data_set);
            update_action(action, data_set);
        }
    }
    free(reason_text);
}

/*!
 * \internal
 * \brief If a start action is unrunnable, block starts of colocated resources
 *
 * \param[in] action    Action to check
 * \param[in] data_set  Cluster working set
 */
void
pcmk__block_colocated_starts(pe_action_t *action, pe_working_set_t *data_set)
{
    GList *gIter = NULL;
    pe_resource_t *rsc = NULL;

    if (!pcmk_is_set(action->flags, pe_action_runnable)
        && pcmk__str_eq(action->task, RSC_START, pcmk__str_casei)) {

        rsc = uber_parent(action->rsc);
        if (rsc->parent) {
            /* For bundles, uber_parent() returns the clone, not the bundle, so
             * the existence of rsc->parent implies this is a bundle.
             * In this case, we need the bundle resource, so that we can check
             * if all containers are stopped/stopping.
             */
            rsc = rsc->parent;
        }
    }

    if ((rsc == NULL) || (rsc->rsc_cons_lhs == NULL)) {
        return;
    }

    // Block colocated starts only if all children (if any) have unrunnable starts
    for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child = (pe_resource_t *)gIter->data;
        pe_action_t *start = find_first_action(child->actions, NULL, RSC_START, NULL);

        if ((start == NULL) || pcmk_is_set(start->flags, pe_action_runnable)) {
            return;
        }
    }

    for (gIter = rsc->rsc_cons_lhs; gIter != NULL; gIter = gIter->next) {
        pcmk__colocation_t *colocate_with = (pcmk__colocation_t *) gIter->data;

        if (colocate_with->score == INFINITY) {
            mark_start_blocked(colocate_with->rsc_lh, action->rsc, data_set);
        }
    }
}

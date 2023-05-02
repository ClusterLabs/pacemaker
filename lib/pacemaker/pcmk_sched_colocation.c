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
#include <pacemaker-internal.h>

#include "crm/common/util.h"
#include "crm/common/xml_internal.h"
#include "crm/msg_xml.h"
#include "libpacemaker_private.h"

#define EXPAND_CONSTRAINT_IDREF(__set, __rsc, __name) do {                      \
        __rsc = pcmk__find_constraint_resource(data_set->resources, __name);    \
        if (__rsc == NULL) {                                                    \
            pcmk__config_err("%s: No resource found for %s", __set, __name);    \
            return;                                                             \
        }                                                                       \
    } while(0)

// Used to temporarily mark a node as unusable
#define INFINITY_HACK   (INFINITY * -100)

static gint
cmp_dependent_priority(gconstpointer a, gconstpointer b)
{
    const pcmk__colocation_t *rsc_constraint1 = (const pcmk__colocation_t *) a;
    const pcmk__colocation_t *rsc_constraint2 = (const pcmk__colocation_t *) b;

    if (a == NULL) {
        return 1;
    }
    if (b == NULL) {
        return -1;
    }

    CRM_ASSERT(rsc_constraint1->dependent != NULL);
    CRM_ASSERT(rsc_constraint1->primary != NULL);

    if (rsc_constraint1->dependent->priority > rsc_constraint2->dependent->priority) {
        return -1;
    }

    if (rsc_constraint1->dependent->priority < rsc_constraint2->dependent->priority) {
        return 1;
    }

    /* Process clones before primitives and groups */
    if (rsc_constraint1->dependent->variant > rsc_constraint2->dependent->variant) {
        return -1;
    }
    if (rsc_constraint1->dependent->variant < rsc_constraint2->dependent->variant) {
        return 1;
    }

    /* @COMPAT scheduler <2.0.0: Process promotable clones before nonpromotable
     * clones (probably unnecessary, but avoids having to update regression
     * tests)
     */
    if (rsc_constraint1->dependent->variant == pe_clone) {
        if (pcmk_is_set(rsc_constraint1->dependent->flags, pe_rsc_promotable)
            && !pcmk_is_set(rsc_constraint2->dependent->flags, pe_rsc_promotable)) {
            return -1;
        } else if (!pcmk_is_set(rsc_constraint1->dependent->flags, pe_rsc_promotable)
            && pcmk_is_set(rsc_constraint2->dependent->flags, pe_rsc_promotable)) {
            return 1;
        }
    }

    return strcmp(rsc_constraint1->dependent->id,
                  rsc_constraint2->dependent->id);
}

static gint
cmp_primary_priority(gconstpointer a, gconstpointer b)
{
    const pcmk__colocation_t *rsc_constraint1 = (const pcmk__colocation_t *) a;
    const pcmk__colocation_t *rsc_constraint2 = (const pcmk__colocation_t *) b;

    if (a == NULL) {
        return 1;
    }
    if (b == NULL) {
        return -1;
    }

    CRM_ASSERT(rsc_constraint1->dependent != NULL);
    CRM_ASSERT(rsc_constraint1->primary != NULL);

    if (rsc_constraint1->primary->priority > rsc_constraint2->primary->priority) {
        return -1;
    }

    if (rsc_constraint1->primary->priority < rsc_constraint2->primary->priority) {
        return 1;
    }

    /* Process clones before primitives and groups */
    if (rsc_constraint1->primary->variant > rsc_constraint2->primary->variant) {
        return -1;
    } else if (rsc_constraint1->primary->variant < rsc_constraint2->primary->variant) {
        return 1;
    }

    /* @COMPAT scheduler <2.0.0: Process promotable clones before nonpromotable
     * clones (probably unnecessary, but avoids having to update regression
     * tests)
     */
    if (rsc_constraint1->primary->variant == pe_clone) {
        if (pcmk_is_set(rsc_constraint1->primary->flags, pe_rsc_promotable)
            && !pcmk_is_set(rsc_constraint2->primary->flags, pe_rsc_promotable)) {
            return -1;
        } else if (!pcmk_is_set(rsc_constraint1->primary->flags, pe_rsc_promotable)
            && pcmk_is_set(rsc_constraint2->primary->flags, pe_rsc_promotable)) {
            return 1;
        }
    }

    return strcmp(rsc_constraint1->primary->id, rsc_constraint2->primary->id);
}

/*!
 * \internal
 * \brief Add a "this with" colocation constraint to a sorted list
 *
 * \param[in,out] list        List of constraints to add \p colocation to
 * \param[in]     colocation  Colocation constraint to add to \p list
 *
 * \note The list will be sorted using cmp_primary_priority().
 */
void
pcmk__add_this_with(GList **list, const pcmk__colocation_t *colocation)
{
    CRM_ASSERT((list != NULL) && (colocation != NULL));

    crm_trace("Adding colocation %s (%s with %s%s%s @%d) "
              "to 'this with' list",
              colocation->id, colocation->dependent->id,
              colocation->primary->id,
              (colocation->node_attribute == NULL)? "" : " using ",
              pcmk__s(colocation->node_attribute, ""),
              colocation->score);
    *list = g_list_insert_sorted(*list, (gpointer) colocation,
                                 cmp_primary_priority);
}

/*!
 * \internal
 * \brief Add a list of "this with" colocation constraints to a list
 *
 * \param[in,out] list      List of constraints to add \p addition to
 * \param[in]     addition  List of colocation constraints to add to \p list
 *
 * \note The lists must be pre-sorted by cmp_primary_priority().
 */
void
pcmk__add_this_with_list(GList **list, GList *addition)
{
    CRM_CHECK((list != NULL), return);

    if (*list == NULL) { // Trivial case for efficiency
        crm_trace("Copying %u 'this with' colocations to new list",
                  g_list_length(addition));
        *list = g_list_copy(addition);
    } else {
        while (addition != NULL) {
            pcmk__add_this_with(list, addition->data);
            addition = addition->next;
        }
    }
}

/*!
 * \internal
 * \brief Add a "with this" colocation constraint to a sorted list
 *
 * \param[in,out] list        List of constraints to add \p colocation to
 * \param[in]     colocation  Colocation constraint to add to \p list
 *
 * \note The list will be sorted using cmp_dependent_priority().
 */
void
pcmk__add_with_this(GList **list, const pcmk__colocation_t *colocation)
{
    CRM_ASSERT((list != NULL) && (colocation != NULL));

    crm_trace("Adding colocation %s (%s with %s%s%s @%d) "
              "to 'with this' list",
              colocation->id, colocation->dependent->id,
              colocation->primary->id,
              (colocation->node_attribute == NULL)? "" : " using ",
              pcmk__s(colocation->node_attribute, ""),
              colocation->score);
    *list = g_list_insert_sorted(*list, (gpointer) colocation,
                                 cmp_dependent_priority);
}

/*!
 * \internal
 * \brief Add a list of "with this" colocation constraints to a list
 *
 * \param[in,out] list      List of constraints to add \p addition to
 * \param[in]     addition  List of colocation constraints to add to \p list
 *
 * \note The lists must be pre-sorted by cmp_dependent_priority().
 */
void
pcmk__add_with_this_list(GList **list, GList *addition)
{
    CRM_CHECK((list != NULL), return);

    if (*list == NULL) { // Trivial case for efficiency
        crm_trace("Copying %u 'with this' colocations to new list",
                  g_list_length(addition));
        *list = g_list_copy(addition);
    } else {
        while (addition != NULL) {
            pcmk__add_with_this(list, addition->data);
            addition = addition->next;
        }
    }
}

/*!
 * \internal
 * \brief Add orderings necessary for an anti-colocation constraint
 *
 * \param[in,out] first_rsc   One resource in an anti-colocation
 * \param[in]     first_role  Anti-colocation role of \p first_rsc
 * \param[in]     then_rsc    Other resource in the anti-colocation
 * \param[in]     then_role   Anti-colocation role of \p then_rsc
 */
static void
anti_colocation_order(pe_resource_t *first_rsc, int first_role,
                      pe_resource_t *then_rsc, int then_role)
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
                                         pe_order_anti_colocation);
        }
    }
}

/*!
 * \internal
 * \brief Add a new colocation constraint to a cluster working set
 *
 * \param[in]     id              XML ID for this constraint
 * \param[in]     node_attr       Colocate by this attribute (NULL for #uname)
 * \param[in]     score           Constraint score
 * \param[in,out] dependent       Resource to be colocated
 * \param[in,out] primary         Resource to colocate \p dependent with
 * \param[in]     dependent_role  Current role of \p dependent
 * \param[in]     primary_role    Current role of \p primary
 * \param[in]     influence       Whether colocation constraint has influence
 * \param[in,out] data_set        Cluster working set to add constraint to
 */
void
pcmk__new_colocation(const char *id, const char *node_attr, int score,
                     pe_resource_t *dependent, pe_resource_t *primary,
                     const char *dependent_role, const char *primary_role,
                     bool influence, pe_working_set_t *data_set)
{
    pcmk__colocation_t *new_con = NULL;

    if (score == 0) {
        crm_trace("Ignoring colocation '%s' because score is 0", id);
        return;
    }
    if ((dependent == NULL) || (primary == NULL)) {
        pcmk__config_err("Ignoring colocation '%s' because resource "
                         "does not exist", id);
        return;
    }

    new_con = calloc(1, sizeof(pcmk__colocation_t));
    if (new_con == NULL) {
        return;
    }

    if (pcmk__str_eq(dependent_role, RSC_ROLE_STARTED_S,
                     pcmk__str_null_matches|pcmk__str_casei)) {
        dependent_role = RSC_ROLE_UNKNOWN_S;
    }

    if (pcmk__str_eq(primary_role, RSC_ROLE_STARTED_S,
                     pcmk__str_null_matches|pcmk__str_casei)) {
        primary_role = RSC_ROLE_UNKNOWN_S;
    }

    new_con->id = id;
    new_con->dependent = dependent;
    new_con->primary = primary;
    new_con->score = score;
    new_con->dependent_role = text2role(dependent_role);
    new_con->primary_role = text2role(primary_role);
    new_con->node_attribute = node_attr;
    new_con->influence = influence;

    if (node_attr == NULL) {
        node_attr = CRM_ATTR_UNAME;
    }

    pe_rsc_trace(dependent, "%s ==> %s (%s %d)",
                 dependent->id, primary->id, node_attr, score);

    pcmk__add_this_with(&(dependent->rsc_cons), new_con);
    pcmk__add_with_this(&(primary->rsc_cons_lhs), new_con);

    data_set->colocation_constraints = g_list_append(data_set->colocation_constraints,
                                                     new_con);

    if (score <= -INFINITY) {
        anti_colocation_order(dependent, new_con->dependent_role, primary,
                              new_con->primary_role);
        anti_colocation_order(primary, new_con->primary_role, dependent,
                              new_con->dependent_role);
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
    const char *ordering = crm_element_value(set, "ordering");
    int local_score = score;
    bool sequential = false;

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

    if (pcmk__xe_get_bool_attr(set, "sequential", &sequential) == pcmk_rc_ok && !sequential) {
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

    int rc = pcmk_rc_ok;
    bool sequential = false;

    if (score == 0) {
        crm_trace("Ignoring colocation '%s' between sets because score is 0",
                  id);
        return;
    }

    rc = pcmk__xe_get_bool_attr(set1, "sequential", &sequential);
    if (rc != pcmk_rc_ok || sequential) {
        // Get the first one
        xml_rsc = first_named_child(set1, XML_TAG_RESOURCE_REF);
        if (xml_rsc != NULL) {
            EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));
        }
    }

    rc = pcmk__xe_get_bool_attr(set2, "sequential", &sequential);
    if (rc != pcmk_rc_ok || sequential) {
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
    const char *dependent_id = crm_element_value(xml_obj,
                                                 XML_COLOC_ATTR_SOURCE);
    const char *primary_id = crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET);
    const char *dependent_role = crm_element_value(xml_obj,
                                                   XML_COLOC_ATTR_SOURCE_ROLE);
    const char *primary_role = crm_element_value(xml_obj,
                                                 XML_COLOC_ATTR_TARGET_ROLE);
    const char *attr = crm_element_value(xml_obj, XML_COLOC_ATTR_NODE_ATTR);

    // @COMPAT: Deprecated since 2.1.5
    const char *dependent_instance = crm_element_value(xml_obj,
                                                       XML_COLOC_ATTR_SOURCE_INSTANCE);
    // @COMPAT: Deprecated since 2.1.5
    const char *primary_instance = crm_element_value(xml_obj,
                                                     XML_COLOC_ATTR_TARGET_INSTANCE);

    pe_resource_t *dependent = pcmk__find_constraint_resource(data_set->resources,
                                                              dependent_id);
    pe_resource_t *primary = pcmk__find_constraint_resource(data_set->resources,
                                                            primary_id);

    if (dependent_instance != NULL) {
        pe_warn_once(pe_wo_coloc_inst,
                     "Support for " XML_COLOC_ATTR_SOURCE_INSTANCE " is "
                     "deprecated and will be removed in a future release.");
    }

    if (primary_instance != NULL) {
        pe_warn_once(pe_wo_coloc_inst,
                     "Support for " XML_COLOC_ATTR_TARGET_INSTANCE " is "
                     "deprecated and will be removed in a future release.");
    }

    if (dependent == NULL) {
        pcmk__config_err("Ignoring constraint '%s' because resource '%s' "
                         "does not exist", id, dependent_id);
        return;

    } else if (primary == NULL) {
        pcmk__config_err("Ignoring constraint '%s' because resource '%s' "
                         "does not exist", id, primary_id);
        return;

    } else if ((dependent_instance != NULL) && !pe_rsc_is_clone(dependent)) {
        pcmk__config_err("Ignoring constraint '%s' because resource '%s' "
                         "is not a clone but instance '%s' was requested",
                         id, dependent_id, dependent_instance);
        return;

    } else if ((primary_instance != NULL) && !pe_rsc_is_clone(primary)) {
        pcmk__config_err("Ignoring constraint '%s' because resource '%s' "
                         "is not a clone but instance '%s' was requested",
                         id, primary_id, primary_instance);
        return;
    }

    if (dependent_instance != NULL) {
        dependent = find_clone_instance(dependent, dependent_instance);
        if (dependent == NULL) {
            pcmk__config_warn("Ignoring constraint '%s' because resource '%s' "
                              "does not have an instance '%s'",
                              id, dependent_id, dependent_instance);
            return;
        }
    }

    if (primary_instance != NULL) {
        primary = find_clone_instance(primary, primary_instance);
        if (primary == NULL) {
            pcmk__config_warn("Ignoring constraint '%s' because resource '%s' "
                              "does not have an instance '%s'",
                              "'%s'", id, primary_id, primary_instance);
            return;
        }
    }

    if (pcmk__xe_attr_is_true(xml_obj, XML_CONS_ATTR_SYMMETRICAL)) {
        pcmk__config_warn("The colocation constraint '"
                          XML_CONS_ATTR_SYMMETRICAL
                          "' attribute has been removed");
    }

    if (score) {
        score_i = char2score(score);
    }

    pcmk__new_colocation(id, attr, score_i, dependent, primary,
                         dependent_role, primary_role,
                         unpack_influence(id, dependent, influence_s), data_set);
}

// \return Standard Pacemaker return code
static int
unpack_colocation_tags(xmlNode *xml_obj, xmlNode **expanded_xml,
                       pe_working_set_t *data_set)
{
    const char *id = NULL;
    const char *dependent_id = NULL;
    const char *primary_id = NULL;
    const char *dependent_role = NULL;
    const char *primary_role = NULL;

    pe_resource_t *dependent = NULL;
    pe_resource_t *primary = NULL;

    pe_tag_t *dependent_tag = NULL;
    pe_tag_t *primary_tag = NULL;

    xmlNode *dependent_set = NULL;
    xmlNode *primary_set = NULL;
    bool any_sets = false;

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
        crm_log_xml_trace(*expanded_xml, "Expanded rsc_colocation");
        return pcmk_rc_ok;
    }

    dependent_id = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE);
    primary_id = crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET);
    if ((dependent_id == NULL) || (primary_id == NULL)) {
        return pcmk_rc_ok;
    }

    if (!pcmk__valid_resource_or_tag(data_set, dependent_id, &dependent,
                                     &dependent_tag)) {
        pcmk__config_err("Ignoring constraint '%s' because '%s' is not a "
                         "valid resource or tag", id, dependent_id);
        return pcmk_rc_unpack_error;
    }

    if (!pcmk__valid_resource_or_tag(data_set, primary_id, &primary,
                                     &primary_tag)) {
        pcmk__config_err("Ignoring constraint '%s' because '%s' is not a "
                         "valid resource or tag", id, primary_id);
        return pcmk_rc_unpack_error;
    }

    if ((dependent != NULL) && (primary != NULL)) {
        /* Neither side references any template/tag. */
        return pcmk_rc_ok;
    }

    if ((dependent_tag != NULL) && (primary_tag != NULL)) {
        // A colocation constraint between two templates/tags makes no sense
        pcmk__config_err("Ignoring constraint '%s' because two templates or "
                         "tags cannot be colocated", id);
        return pcmk_rc_unpack_error;
    }

    dependent_role = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE_ROLE);
    primary_role = crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET_ROLE);

    *expanded_xml = copy_xml(xml_obj);

    // Convert template/tag reference in "rsc" into resource_set under constraint
    if (!pcmk__tag_to_set(*expanded_xml, &dependent_set, XML_COLOC_ATTR_SOURCE,
                          true, data_set)) {
        free_xml(*expanded_xml);
        *expanded_xml = NULL;
        return pcmk_rc_unpack_error;
    }

    if (dependent_set != NULL) {
        if (dependent_role != NULL) {
            // Move "rsc-role" into converted resource_set as "role"
            crm_xml_add(dependent_set, "role", dependent_role);
            xml_remove_prop(*expanded_xml, XML_COLOC_ATTR_SOURCE_ROLE);
        }
        any_sets = true;
    }

    // Convert template/tag reference in "with-rsc" into resource_set under constraint
    if (!pcmk__tag_to_set(*expanded_xml, &primary_set, XML_COLOC_ATTR_TARGET,
                          true, data_set)) {
        free_xml(*expanded_xml);
        *expanded_xml = NULL;
        return pcmk_rc_unpack_error;
    }

    if (primary_set != NULL) {
        if (primary_role != NULL) {
            // Move "with-rsc-role" into converted resource_set as "role"
            crm_xml_add(primary_set, "role", primary_role);
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
 * \param[in,out] xml_obj   Colocation constraint XML to unpack
 * \param[in,out] data_set  Cluster working set to add constraint to
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

/*!
 * \internal
 * \brief Make actions of a given type unrunnable for a given resource
 *
 * \param[in,out] rsc     Resource whose actions should be blocked
 * \param[in]     task    Name of action to block
 * \param[in]     reason  Unrunnable start action causing the block
 */
static void
mark_action_blocked(pe_resource_t *rsc, const char *task,
                    const pe_resource_t *reason)
{
    char *reason_text = crm_strdup_printf("colocation with %s", reason->id);

    for (GList *gIter = rsc->actions; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

        if (pcmk_is_set(action->flags, pe_action_runnable)
            && pcmk__str_eq(action->task, task, pcmk__str_casei)) {

            pe__clear_action_flags(action, pe_action_runnable);
            pe_action_set_reason(action, reason_text, false);
            pcmk__block_colocation_dependents(action, rsc->cluster);
            pcmk__update_action_for_orderings(action, rsc->cluster);
        }
    }

    // If parent resource can't perform an action, neither can any children
    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        mark_action_blocked((pe_resource_t *) (iter->data), task, reason);
    }
    free(reason_text);
}

/*!
 * \internal
 * \brief If an action is unrunnable, block any relevant dependent actions
 *
 * If a given action is an unrunnable start or promote, block the start or
 * promote actions of resources colocated with it, as appropriate to the
 * colocations' configured roles.
 *
 * \param[in,out] action    Action to check
 * \param[in]     data_set  Cluster working set (ignored)
 */
void
pcmk__block_colocation_dependents(pe_action_t *action,
                                  pe_working_set_t *data_set)
{
    GList *gIter = NULL;
    GList *colocations = NULL;
    pe_resource_t *rsc = NULL;
    bool is_start = false;

    if (pcmk_is_set(action->flags, pe_action_runnable)) {
        return; // Only unrunnable actions block dependents
    }

    is_start = pcmk__str_eq(action->task, RSC_START, pcmk__str_none);
    if (!is_start && !pcmk__str_eq(action->task, RSC_PROMOTE, pcmk__str_none)) {
        return; // Only unrunnable starts and promotes block dependents
    }

    CRM_ASSERT(action->rsc != NULL); // Start and promote are resource actions

    /* If this resource is part of a collective resource, dependents are blocked
     * only if all instances of the collective are unrunnable, so check the
     * collective resource.
     */
    rsc = uber_parent(action->rsc);
    if (rsc->parent != NULL) {
        rsc = rsc->parent; // Bundle
    }

    // Colocation fails only if entire primary can't reach desired role
    for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child = (pe_resource_t *) gIter->data;
        pe_action_t *child_action = find_first_action(child->actions, NULL,
                                                      action->task, NULL);

        if ((child_action == NULL)
            || pcmk_is_set(child_action->flags, pe_action_runnable)) {
            crm_trace("Not blocking %s colocation dependents because "
                      "at least %s has runnable %s",
                      rsc->id, child->id, action->task);
            return; // At least one child can reach desired role
        }
    }

    crm_trace("Blocking %s colocation dependents due to unrunnable %s %s",
              rsc->id, action->rsc->id, action->task);

    // Check each colocation where this resource is primary
    colocations = pcmk__with_this_colocations(rsc);
    for (gIter = colocations; gIter != NULL; gIter = gIter->next) {
        pcmk__colocation_t *colocation = (pcmk__colocation_t *) gIter->data;

        if (colocation->score < INFINITY) {
            continue; // Only mandatory colocations block dependent
        }

        /* If the primary can't start, the dependent can't reach its colocated
         * role, regardless of what the primary or dependent colocation role is.
         *
         * If the primary can't be promoted, the dependent can't reach its
         * colocated role if the primary's colocation role is promoted.
         */
        if (!is_start && (colocation->primary_role != RSC_ROLE_PROMOTED)) {
            continue;
        }

        // Block the dependent from reaching its colocated role
        if (colocation->dependent_role == RSC_ROLE_PROMOTED) {
            mark_action_blocked(colocation->dependent, RSC_PROMOTE,
                                action->rsc);
        } else {
            mark_action_blocked(colocation->dependent, RSC_START, action->rsc);
        }
    }
    g_list_free(colocations);
}

/*!
 * \internal
 * \brief Determine how a colocation constraint should affect a resource
 *
 * Colocation constraints have different effects at different points in the
 * scheduler sequence. Initially, they affect a resource's location; once that
 * is determined, then for promotable clones they can affect a resource
 * instance's role; after both are determined, the constraints no longer matter.
 * Given a specific colocation constraint, check what has been done so far to
 * determine what should be affected at the current point in the scheduler.
 *
 * \param[in] dependent   Dependent resource in colocation
 * \param[in] primary     Primary resource in colocation
 * \param[in] colocation  Colocation constraint
 * \param[in] preview     If true, pretend resources have already been allocated
 *
 * \return How colocation constraint should be applied at this point
 */
enum pcmk__coloc_affects
pcmk__colocation_affects(const pe_resource_t *dependent,
                         const pe_resource_t *primary,
                         const pcmk__colocation_t *colocation, bool preview)
{
    if (!preview && pcmk_is_set(primary->flags, pe_rsc_provisional)) {
        // Primary resource has not been allocated yet, so we can't do anything
        return pcmk__coloc_affects_nothing;
    }

    if ((colocation->dependent_role >= RSC_ROLE_UNPROMOTED)
        && (dependent->parent != NULL)
        && pcmk_is_set(dependent->parent->flags, pe_rsc_promotable)
        && !pcmk_is_set(dependent->flags, pe_rsc_provisional)) {

        /* This is a colocation by role, and the dependent is a promotable clone
         * that has already been allocated, so the colocation should now affect
         * the role.
         */
        return pcmk__coloc_affects_role;
    }

    if (!preview && !pcmk_is_set(dependent->flags, pe_rsc_provisional)) {
        /* The dependent resource has already been through allocation, so the
         * constraint no longer has any effect. Log an error if a mandatory
         * colocation constraint has been violated.
         */

        const pe_node_t *primary_node = primary->allocated_to;

        if (dependent->allocated_to == NULL) {
            crm_trace("Skipping colocation '%s': %s will not run anywhere",
                      colocation->id, dependent->id);

        } else if (colocation->score >= INFINITY) {
            // Dependent resource must colocate with primary resource

            if ((primary_node == NULL) ||
                (primary_node->details != dependent->allocated_to->details)) {
                crm_err("%s must be colocated with %s but is not (%s vs. %s)",
                        dependent->id, primary->id,
                        pe__node_name(dependent->allocated_to),
                        pe__node_name(primary_node));
            }

        } else if (colocation->score <= -CRM_SCORE_INFINITY) {
            // Dependent resource must anti-colocate with primary resource

            if ((primary_node != NULL) &&
                (dependent->allocated_to->details == primary_node->details)) {
                crm_err("%s and %s must be anti-colocated but are allocated "
                        "to the same node (%s)",
                        dependent->id, primary->id, pe__node_name(primary_node));
            }
        }
        return pcmk__coloc_affects_nothing;
    }

    if ((colocation->score > 0)
        && (colocation->dependent_role != RSC_ROLE_UNKNOWN)
        && (colocation->dependent_role != dependent->next_role)) {

        crm_trace("Skipping colocation '%s': dependent limited to %s role "
                  "but %s next role is %s",
                  colocation->id, role2text(colocation->dependent_role),
                  dependent->id, role2text(dependent->next_role));
        return pcmk__coloc_affects_nothing;
    }

    if ((colocation->score > 0)
        && (colocation->primary_role != RSC_ROLE_UNKNOWN)
        && (colocation->primary_role != primary->next_role)) {

        crm_trace("Skipping colocation '%s': primary limited to %s role "
                  "but %s next role is %s",
                  colocation->id, role2text(colocation->primary_role),
                  primary->id, role2text(primary->next_role));
        return pcmk__coloc_affects_nothing;
    }

    if ((colocation->score < 0)
        && (colocation->dependent_role != RSC_ROLE_UNKNOWN)
        && (colocation->dependent_role == dependent->next_role)) {
        crm_trace("Skipping anti-colocation '%s': dependent role %s matches",
                  colocation->id, role2text(colocation->dependent_role));
        return pcmk__coloc_affects_nothing;
    }

    if ((colocation->score < 0)
        && (colocation->primary_role != RSC_ROLE_UNKNOWN)
        && (colocation->primary_role == primary->next_role)) {
        crm_trace("Skipping anti-colocation '%s': primary role %s matches",
                  colocation->id, role2text(colocation->primary_role));
        return pcmk__coloc_affects_nothing;
    }

    return pcmk__coloc_affects_location;
}

/*!
 * \internal
 * \brief Apply colocation to dependent for allocation purposes
 *
 * Update the allowed node weights of the dependent resource in a colocation,
 * for the purposes of allocating it to a node
 *
 * \param[in,out] dependent   Dependent resource in colocation
 * \param[in]     primary     Primary resource in colocation
 * \param[in]     colocation  Colocation constraint
 */
void
pcmk__apply_coloc_to_weights(pe_resource_t *dependent,
                             const pe_resource_t *primary,
                             const pcmk__colocation_t *colocation)
{
    const char *attribute = CRM_ATTR_ID;
    const char *value = NULL;
    GHashTable *work = NULL;
    GHashTableIter iter;
    pe_node_t *node = NULL;

    if (colocation->node_attribute != NULL) {
        attribute = colocation->node_attribute;
    }

    if (primary->allocated_to != NULL) {
        value = pe_node_attribute_raw(primary->allocated_to, attribute);

    } else if (colocation->score < 0) {
        // Nothing to do (anti-colocation with something that is not running)
        return;
    }

    work = pcmk__copy_node_table(dependent->allowed_nodes);

    g_hash_table_iter_init(&iter, work);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
        if (primary->allocated_to == NULL) {
            node->weight = pcmk__add_scores(-colocation->score, node->weight);
            pe_rsc_trace(dependent,
                         "Applied %s to %s score on %s (now %s after "
                         "subtracting %s because primary %s inactive)",
                         colocation->id, dependent->id, pe__node_name(node),
                         pcmk_readable_score(node->weight),
                         pcmk_readable_score(colocation->score), primary->id);

        } else if (pcmk__str_eq(pe_node_attribute_raw(node, attribute), value,
                                pcmk__str_casei)) {
            /* Add colocation score only if optional (or minus infinity). A
             * mandatory colocation is a requirement rather than a preference,
             * so we don't need to consider it for relative assignment purposes.
             * The resource will simply be forbidden from running on the node if
             * the primary isn't active there (via the condition above).
             */
            if (colocation->score < CRM_SCORE_INFINITY) {
                node->weight = pcmk__add_scores(colocation->score,
                                                node->weight);
                pe_rsc_trace(dependent,
                             "Applied %s to %s score on %s (now %s after "
                             "adding %s)",
                             colocation->id, dependent->id, pe__node_name(node),
                             pcmk_readable_score(node->weight),
                             pcmk_readable_score(colocation->score));
            }

        } else if (colocation->score >= CRM_SCORE_INFINITY) {
            /* Only mandatory colocations are relevant when the colocation
             * attribute doesn't match, because an attribute not matching is not
             * a negative preference -- the colocation is simply relevant only
             * where it matches.
             */
            node->weight = -CRM_SCORE_INFINITY;
            pe_rsc_trace(dependent,
                         "Banned %s from %s because colocation %s attribute %s "
                         "does not match",
                         dependent->id, pe__node_name(node), colocation->id,
                         attribute);
        }
    }

    if ((colocation->score <= -INFINITY) || (colocation->score >= INFINITY)
        || pcmk__any_node_available(work)) {

        g_hash_table_destroy(dependent->allowed_nodes);
        dependent->allowed_nodes = work;
        work = NULL;

    } else {
        pe_rsc_info(dependent,
                    "%s: Rolling back scores from %s (no available nodes)",
                    dependent->id, primary->id);
    }

    if (work != NULL) {
        g_hash_table_destroy(work);
    }
}

/*!
 * \internal
 * \brief Apply colocation to dependent for role purposes
 *
 * Update the priority of the dependent resource in a colocation, for the
 * purposes of selecting its role
 *
 * \param[in,out] dependent   Dependent resource in colocation
 * \param[in]     primary     Primary resource in colocation
 * \param[in]     colocation  Colocation constraint
 */
void
pcmk__apply_coloc_to_priority(pe_resource_t *dependent,
                              const pe_resource_t *primary,
                              const pcmk__colocation_t *colocation)
{
    const char *dependent_value = NULL;
    const char *primary_value = NULL;
    const char *attribute = CRM_ATTR_ID;
    int score_multiplier = 1;

    if ((primary->allocated_to == NULL) || (dependent->allocated_to == NULL)) {
        return;
    }

    if (colocation->node_attribute != NULL) {
        attribute = colocation->node_attribute;
    }

    dependent_value = pe_node_attribute_raw(dependent->allocated_to, attribute);
    primary_value = pe_node_attribute_raw(primary->allocated_to, attribute);

    if (!pcmk__str_eq(dependent_value, primary_value, pcmk__str_casei)) {
        if ((colocation->score == INFINITY)
            && (colocation->dependent_role == RSC_ROLE_PROMOTED)) {
            dependent->priority = -INFINITY;
        }
        return;
    }

    if ((colocation->primary_role != RSC_ROLE_UNKNOWN)
        && (colocation->primary_role != primary->next_role)) {
        return;
    }

    if (colocation->dependent_role == RSC_ROLE_UNPROMOTED) {
        score_multiplier = -1;
    }

    dependent->priority = pcmk__add_scores(score_multiplier * colocation->score,
                                           dependent->priority);
    pe_rsc_trace(dependent,
                 "Applied %s to %s promotion priority (now %s after %s %s)",
                 colocation->id, dependent->id,
                 pcmk_readable_score(dependent->priority),
                 ((score_multiplier == 1)? "adding" : "subtracting"),
                 pcmk_readable_score(colocation->score));
}

/*!
 * \internal
 * \brief Find score of highest-scored node that matches colocation attribute
 *
 * \param[in] rsc    Resource whose allowed nodes should be searched
 * \param[in] attr   Colocation attribute name (must not be NULL)
 * \param[in] value  Colocation attribute value to require
 */
static int
best_node_score_matching_attr(const pe_resource_t *rsc, const char *attr,
                              const char *value)
{
    GHashTableIter iter;
    pe_node_t *node = NULL;
    int best_score = -INFINITY;
    const char *best_node = NULL;

    // Find best allowed node with matching attribute
    g_hash_table_iter_init(&iter, rsc->allowed_nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **) &node)) {

        if ((node->weight > best_score) && pcmk__node_available(node, false, false)
            && pcmk__str_eq(value, pe_node_attribute_raw(node, attr), pcmk__str_casei)) {

            best_score = node->weight;
            best_node = node->details->uname;
        }
    }

    if (!pcmk__str_eq(attr, CRM_ATTR_UNAME, pcmk__str_casei)) {
        if (best_node == NULL) {
            crm_info("No allowed node for %s matches node attribute %s=%s",
                     rsc->id, attr, value);
        } else {
            crm_info("Allowed node %s for %s had best score (%d) "
                     "of those matching node attribute %s=%s",
                     best_node, rsc->id, best_score, attr, value);
        }
    }
    return best_score;
}

/*!
 * \internal
 * \brief Add resource's colocation matches to current node allocation scores
 *
 * For each node in a given table, if any of a given resource's allowed nodes
 * have a matching value for the colocation attribute, add the highest of those
 * nodes' scores to the node's score.
 *
 * \param[in,out] nodes  Hash table of nodes with allocation scores so far
 * \param[in]     rsc    Resource whose allowed nodes should be compared
 * \param[in]     attr   Colocation attribute that must match (NULL for default)
 * \param[in]     factor Factor by which to multiply scores being added
 * \param[in]     only_positive  Whether to add only positive scores
 */
static void
add_node_scores_matching_attr(GHashTable *nodes, const pe_resource_t *rsc,
                              const char *attr, float factor,
                              bool only_positive)
{
    GHashTableIter iter;
    pe_node_t *node = NULL;

    if (attr == NULL) {
        attr = CRM_ATTR_UNAME;
    }

    // Iterate through each node
    g_hash_table_iter_init(&iter, nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
        float weight_f = 0;
        int weight = 0;
        int score = 0;
        int new_score = 0;

        score = best_node_score_matching_attr(rsc, attr,
                                              pe_node_attribute_raw(node, attr));

        if ((factor < 0) && (score < 0)) {
            /* Negative preference for a node with a negative score
             * should not become a positive preference.
             *
             * @TODO Consider filtering only if weight is -INFINITY
             */
            crm_trace("%s: Filtering %d + %f * %d (double negative disallowed)",
                      pe__node_name(node), node->weight, factor, score);
            continue;
        }

        if (node->weight == INFINITY_HACK) {
            crm_trace("%s: Filtering %d + %f * %d (node was marked unusable)",
                      pe__node_name(node), node->weight, factor, score);
            continue;
        }

        weight_f = factor * score;

        // Round the number; see http://c-faq.com/fp/round.html
        weight = (int) ((weight_f < 0)? (weight_f - 0.5) : (weight_f + 0.5));

        /* Small factors can obliterate the small scores that are often actually
         * used in configurations. If the score and factor are nonzero, ensure
         * that the result is nonzero as well.
         */
        if ((weight == 0) && (score != 0)) {
            if (factor > 0.0) {
                weight = 1;
            } else if (factor < 0.0) {
                weight = -1;
            }
        }

        new_score = pcmk__add_scores(weight, node->weight);

        if (only_positive && (new_score < 0) && (node->weight > 0)) {
            crm_trace("%s: Filtering %d + %f * %d = %d "
                      "(negative disallowed, marking node unusable)",
                      pe__node_name(node), node->weight, factor, score,
                      new_score);
            node->weight = INFINITY_HACK;
            continue;
        }

        if (only_positive && (new_score < 0) && (node->weight == 0)) {
            crm_trace("%s: Filtering %d + %f * %d = %d (negative disallowed)",
                      pe__node_name(node), node->weight, factor, score,
                      new_score);
            continue;
        }

        crm_trace("%s: %d + %f * %d = %d", pe__node_name(node),
                  node->weight, factor, score, new_score);
        node->weight = new_score;
    }
}

/*!
 * \internal
 * \brief Update nodes with scores of colocated resources' nodes
 *
 * Given a table of nodes and a resource, update the nodes' scores with the
 * scores of the best nodes matching the attribute used for each of the
 * resource's relevant colocations.
 *
 * \param[in,out] rsc      Resource to check colocations for
 * \param[in]     log_id   Resource ID to use in logs (if NULL, use \p rsc ID)
 * \param[in,out] nodes    Nodes to update
 * \param[in]     attr     Colocation attribute (NULL to use default)
 * \param[in]     factor   Incorporate scores multiplied by this factor
 * \param[in]     flags    Bitmask of enum pcmk__coloc_select values
 *
 * \note The caller remains responsible for freeing \p *nodes.
 */
void
pcmk__add_colocated_node_scores(pe_resource_t *rsc, const char *log_id,
                                GHashTable **nodes, const char *attr,
                                float factor, uint32_t flags)
{
    GHashTable *work = NULL;

    CRM_CHECK((rsc != NULL) && (nodes != NULL), return);

    if (log_id == NULL) {
        log_id = rsc->id;
    }

    // Avoid infinite recursion
    if (pcmk_is_set(rsc->flags, pe_rsc_merging)) {
        pe_rsc_info(rsc, "%s: Breaking dependency loop at %s",
                    log_id, rsc->id);
        return;
    }
    pe__set_resource_flags(rsc, pe_rsc_merging);

    if (*nodes == NULL) {
        /* Only cmp_resources() passes a NULL nodes table, which indicates we
         * should initialize it with the resource's allowed node scores.
         */
        work = pcmk__copy_node_table(rsc->allowed_nodes);
    } else {
        pe_rsc_trace(rsc, "%s: Merging scores from %s (at %.6f)",
                     log_id, rsc->id, factor);
        work = pcmk__copy_node_table(*nodes);
        add_node_scores_matching_attr(work, rsc, attr, factor,
                                      pcmk_is_set(flags,
                                                  pcmk__coloc_select_nonnegative));
    }

    if (work == NULL) {
        pe__clear_resource_flags(rsc, pe_rsc_merging);
        return;
    }

    if (pcmk__any_node_available(work)) {
        GList *colocations = NULL;

        if (pcmk_is_set(flags, pcmk__coloc_select_this_with)) {
            colocations = pcmk__this_with_colocations(rsc);
            pe_rsc_trace(rsc,
                         "Checking additional %d optional '%s with' constraints",
                         g_list_length(colocations), rsc->id);
        } else {
            colocations = pcmk__with_this_colocations(rsc);
            pe_rsc_trace(rsc,
                         "Checking additional %d optional 'with %s' constraints",
                         g_list_length(colocations), rsc->id);
        }
        flags |= pcmk__coloc_select_active;

        for (GList *iter = colocations; iter != NULL; iter = iter->next) {
            pcmk__colocation_t *constraint = (pcmk__colocation_t *) iter->data;

            pe_resource_t *other = NULL;
            float other_factor = factor * constraint->score / (float) INFINITY;

            if (pcmk_is_set(flags, pcmk__coloc_select_this_with)) {
                other = constraint->primary;
            } else if (!pcmk__colocation_has_influence(constraint, NULL)) {
                continue;
            } else {
                other = constraint->dependent;
            }

            pe_rsc_trace(rsc, "Optionally merging score of '%s' constraint (%s with %s)",
                         constraint->id, constraint->dependent->id,
                         constraint->primary->id);
            other->cmds->add_colocated_node_scores(other, log_id, &work,
                                                   constraint->node_attribute,
                                                   other_factor, flags);
            pe__show_node_weights(true, NULL, log_id, work, rsc->cluster);
        }
        g_list_free(colocations);

    } else if (pcmk_is_set(flags, pcmk__coloc_select_active)) {
        pe_rsc_info(rsc, "%s: Rolling back optional scores from %s",
                    log_id, rsc->id);
        g_hash_table_destroy(work);
        pe__clear_resource_flags(rsc, pe_rsc_merging);
        return;
    }


    if (pcmk_is_set(flags, pcmk__coloc_select_nonnegative)) {
        pe_node_t *node = NULL;
        GHashTableIter iter;

        g_hash_table_iter_init(&iter, work);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
            if (node->weight == INFINITY_HACK) {
                node->weight = 1;
            }
        }
    }

    if (*nodes != NULL) {
       g_hash_table_destroy(*nodes);
    }
    *nodes = work;

    pe__clear_resource_flags(rsc, pe_rsc_merging);
}

/*!
 * \internal
 * \brief Apply a "with this" colocation to a resource's allowed node scores
 *
 * \param[in,out] data       Colocation to apply
 * \param[in,out] user_data  Resource being assigned
 */
void
pcmk__add_dependent_scores(gpointer data, gpointer user_data)
{
    pcmk__colocation_t *colocation = (pcmk__colocation_t *) data;
    pe_resource_t *rsc = (pe_resource_t *) user_data;

    pe_resource_t *other = colocation->dependent;
    const float factor = colocation->score / (float) INFINITY;
    uint32_t flags = pcmk__coloc_select_active;

    if (!pcmk__colocation_has_influence(colocation, NULL)) {
        return;
    }
    if (rsc->variant == pe_clone) {
        flags |= pcmk__coloc_select_nonnegative;
    }
    pe_rsc_trace(rsc,
                 "%s: Incorporating attenuated %s assignment scores due "
                 "to colocation %s", rsc->id, other->id, colocation->id);
    other->cmds->add_colocated_node_scores(other, rsc->id, &rsc->allowed_nodes,
                                           colocation->node_attribute, factor,
                                           flags);
}

/*!
 * \internal
 * \brief Get all colocations affecting a resource as the primary
 *
 * \param[in] rsc  Resource to get colocations for
 *
 * \return Newly allocated list of colocations affecting \p rsc as primary
 *
 * \note This is a convenience wrapper for the with_this_colocations() method.
 */
GList *
pcmk__with_this_colocations(const pe_resource_t *rsc)
{
    GList *list = NULL;

    rsc->cmds->with_this_colocations(rsc, rsc, &list);
    return list;
}

/*!
 * \internal
 * \brief Get all colocations affecting a resource as the dependent
 *
 * \param[in] rsc  Resource to get colocations for
 *
 * \return Newly allocated list of colocations affecting \p rsc as dependent
 *
 * \note This is a convenience wrapper for the this_with_colocations() method.
 */
GList *
pcmk__this_with_colocations(const pe_resource_t *rsc)
{
    GList *list = NULL;

    rsc->cmds->this_with_colocations(rsc, rsc, &list);
    return list;
}

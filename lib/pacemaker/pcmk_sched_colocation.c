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
#include <crm/common/scheduler.h>
#include <crm/common/scheduler_internal.h>
#include <crm/pengine/status.h>
#include <pacemaker-internal.h>

#include "crm/common/util.h"
#include "crm/common/xml_internal.h"
#include "crm/common/xml.h"
#include "libpacemaker_private.h"

// Used to temporarily mark a node as unusable
#define INFINITY_HACK   (PCMK_SCORE_INFINITY * -100)

/*!
 * \internal
 * \brief Get the value of a colocation's node attribute
 *
 * \param[in] node  Node on which to look up the attribute
 * \param[in] attr  Name of attribute to look up
 * \param[in] rsc   Resource on whose behalf to look up the attribute
 *
 * \return Value of \p attr on \p node or on the host of \p node, as appropriate
 */
const char *
pcmk__colocation_node_attr(const pcmk_node_t *node, const char *attr,
                           const pcmk_resource_t *rsc)
{
    const char *target = NULL;

    /* A resource colocated with a bundle or its primitive can't run on the
     * bundle node itself (where only the primitive, if any, can run). Instead,
     * we treat it as a colocation with the bundle's containers, so always look
     * up colocation node attributes on the container host.
     */
    if (pcmk__is_bundle_node(node) && pcmk__is_bundled(rsc)
        && (pe__const_top_resource(rsc, false) == pe__bundled_resource(rsc))) {
        target = PCMK_VALUE_HOST;

    } else if (rsc != NULL) {
        target = g_hash_table_lookup(rsc->priv->meta,
                                     PCMK_META_CONTAINER_ATTRIBUTE_TARGET);
    }

    return pcmk__node_attr(node, attr, target, pcmk__rsc_node_assigned);
}

/*!
 * \internal
 * \brief Compare two colocations according to priority
 *
 * Compare two colocations according to the order in which they should be
 * considered, based on either their dependent resources or their primary
 * resources -- preferring (in order):
 *  * Colocation that is not \c NULL
 *  * Colocation whose resource has higher priority
 *  * Colocation whose resource is of a higher-level variant
 *    (bundle > clone > group > primitive)
 *  * Colocation whose resource is promotable, if both are clones
 *  * Colocation whose resource has lower ID in lexicographic order
 *
 * \param[in] colocation1  First colocation to compare
 * \param[in] colocation2  Second colocation to compare
 * \param[in] dependent    If \c true, compare colocations by dependent
 *                         priority; otherwise compare them by primary priority
 *
 * \return A negative number if \p colocation1 should be considered first,
 *         a positive number if \p colocation2 should be considered first,
 *         or 0 if order doesn't matter
 */
static gint
cmp_colocation_priority(const pcmk__colocation_t *colocation1,
                        const pcmk__colocation_t *colocation2, bool dependent)
{
    const pcmk_resource_t *rsc1 = NULL;
    const pcmk_resource_t *rsc2 = NULL;

    if (colocation1 == NULL) {
        return 1;
    }
    if (colocation2 == NULL) {
        return -1;
    }

    if (dependent) {
        rsc1 = colocation1->dependent;
        rsc2 = colocation2->dependent;
        pcmk__assert(colocation1->primary != NULL);
    } else {
        rsc1 = colocation1->primary;
        rsc2 = colocation2->primary;
        pcmk__assert(colocation1->dependent != NULL);
    }
    pcmk__assert((rsc1 != NULL) && (rsc2 != NULL));

    if (rsc1->priv->priority > rsc2->priv->priority) {
        return -1;
    }
    if (rsc1->priv->priority < rsc2->priv->priority) {
        return 1;
    }

    // Process clones before primitives and groups
    if (rsc1->priv->variant > rsc2->priv->variant) {
        return -1;
    }
    if (rsc1->priv->variant < rsc2->priv->variant) {
        return 1;
    }

    /* @COMPAT scheduler <2.0.0: Process promotable clones before nonpromotable
     * clones (probably unnecessary, but avoids having to update regression
     * tests)
     */
    if (pcmk__is_clone(rsc1)) {
        if (pcmk_is_set(rsc1->flags, pcmk__rsc_promotable)
            && !pcmk_is_set(rsc2->flags, pcmk__rsc_promotable)) {
            return -1;
        }
        if (!pcmk_is_set(rsc1->flags, pcmk__rsc_promotable)
            && pcmk_is_set(rsc2->flags, pcmk__rsc_promotable)) {
            return 1;
        }
    }

    return strcmp(rsc1->id, rsc2->id);
}

/*!
 * \internal
 * \brief Compare two colocations according to priority based on dependents
 *
 * Compare two colocations according to the order in which they should be
 * considered, based on their dependent resources -- preferring (in order):
 *  * Colocation that is not \c NULL
 *  * Colocation whose resource has higher priority
 *  * Colocation whose resource is of a higher-level variant
 *    (bundle > clone > group > primitive)
 *  * Colocation whose resource is promotable, if both are clones
 *  * Colocation whose resource has lower ID in lexicographic order
 *
 * \param[in] a  First colocation to compare
 * \param[in] b  Second colocation to compare
 *
 * \return A negative number if \p a should be considered first,
 *         a positive number if \p b should be considered first,
 *         or 0 if order doesn't matter
 */
static gint
cmp_dependent_priority(gconstpointer a, gconstpointer b)
{
    return cmp_colocation_priority(a, b, true);
}

/*!
 * \internal
 * \brief Compare two colocations according to priority based on primaries
 *
 * Compare two colocations according to the order in which they should be
 * considered, based on their primary resources -- preferring (in order):
 *  * Colocation that is not \c NULL
 *  * Colocation whose primary has higher priority
 *  * Colocation whose primary is of a higher-level variant
 *    (bundle > clone > group > primitive)
 *  * Colocation whose primary is promotable, if both are clones
 *  * Colocation whose primary has lower ID in lexicographic order
 *
 * \param[in] a  First colocation to compare
 * \param[in] b  Second colocation to compare
 *
 * \return A negative number if \p a should be considered first,
 *         a positive number if \p b should be considered first,
 *         or 0 if order doesn't matter
 */
static gint
cmp_primary_priority(gconstpointer a, gconstpointer b)
{
    return cmp_colocation_priority(a, b, false);
}

/*!
 * \internal
 * \brief Add a "this with" colocation constraint to a sorted list
 *
 * \param[in,out] list        List of constraints to add \p colocation to
 * \param[in]     colocation  Colocation constraint to add to \p list
 * \param[in]     rsc         Resource whose colocations we're getting (for
 *                            logging only)
 *
 * \note The list will be sorted using cmp_primary_priority().
 */
void
pcmk__add_this_with(GList **list, const pcmk__colocation_t *colocation,
                    const pcmk_resource_t *rsc)
{
    pcmk__assert((list != NULL) && (colocation != NULL) && (rsc != NULL));

    pcmk__rsc_trace(rsc,
                    "Adding colocation %s (%s with %s using %s @%s) to "
                    "'this with' list for %s",
                    colocation->id, colocation->dependent->id,
                    colocation->primary->id, colocation->node_attribute,
                    pcmk_readable_score(colocation->score), rsc->id);
    *list = g_list_insert_sorted(*list, (gpointer) colocation,
                                 cmp_primary_priority);
}

/*!
 * \internal
 * \brief Add a list of "this with" colocation constraints to a list
 *
 * \param[in,out] list      List of constraints to add \p addition to
 * \param[in]     addition  List of colocation constraints to add to \p list
 * \param[in]     rsc       Resource whose colocations we're getting (for
 *                          logging only)
 *
 * \note The lists must be pre-sorted by cmp_primary_priority().
 */
void
pcmk__add_this_with_list(GList **list, GList *addition,
                         const pcmk_resource_t *rsc)
{
    pcmk__assert((list != NULL) && (rsc != NULL));

    pcmk__if_tracing(
        {}, // Always add each colocation individually if tracing
        {
            if (*list == NULL) {
                // Trivial case for efficiency if not tracing
                *list = g_list_copy(addition);
                return;
            }
        }
    );

    for (const GList *iter = addition; iter != NULL; iter = iter->next) {
        pcmk__add_this_with(list, addition->data, rsc);
    }
}

/*!
 * \internal
 * \brief Add a "with this" colocation constraint to a sorted list
 *
 * \param[in,out] list        List of constraints to add \p colocation to
 * \param[in]     colocation  Colocation constraint to add to \p list
 * \param[in]     rsc         Resource whose colocations we're getting (for
 *                            logging only)
 *
 * \note The list will be sorted using cmp_dependent_priority().
 */
void
pcmk__add_with_this(GList **list, const pcmk__colocation_t *colocation,
                    const pcmk_resource_t *rsc)
{
    pcmk__assert((list != NULL) && (colocation != NULL) && (rsc != NULL));

    pcmk__rsc_trace(rsc,
                    "Adding colocation %s (%s with %s using %s @%s) to "
                    "'with this' list for %s",
                    colocation->id, colocation->dependent->id,
                    colocation->primary->id, colocation->node_attribute,
                    pcmk_readable_score(colocation->score), rsc->id);
    *list = g_list_insert_sorted(*list, (gpointer) colocation,
                                 cmp_dependent_priority);
}

/*!
 * \internal
 * \brief Add a list of "with this" colocation constraints to a list
 *
 * \param[in,out] list      List of constraints to add \p addition to
 * \param[in]     addition  List of colocation constraints to add to \p list
 * \param[in]     rsc       Resource whose colocations we're getting (for
 *                          logging only)
 *
 * \note The lists must be pre-sorted by cmp_dependent_priority().
 */
void
pcmk__add_with_this_list(GList **list, GList *addition,
                         const pcmk_resource_t *rsc)
{
    pcmk__assert((list != NULL) && (rsc != NULL));

    pcmk__if_tracing(
        {}, // Always add each colocation individually if tracing
        {
            if (*list == NULL) {
                // Trivial case for efficiency if not tracing
                *list = g_list_copy(addition);
                return;
            }
        }
    );

    for (const GList *iter = addition; iter != NULL; iter = iter->next) {
        pcmk__add_with_this(list, addition->data, rsc);
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
anti_colocation_order(pcmk_resource_t *first_rsc, int first_role,
                      pcmk_resource_t *then_rsc, int then_role)
{
    const char *first_tasks[] = { NULL, NULL };
    const char *then_tasks[] = { NULL, NULL };

    /* Actions to make first_rsc lose first_role */
    if (first_role == pcmk_role_promoted) {
        first_tasks[0] = PCMK_ACTION_DEMOTE;

    } else {
        first_tasks[0] = PCMK_ACTION_STOP;

        if (first_role == pcmk_role_unpromoted) {
            first_tasks[1] = PCMK_ACTION_PROMOTE;
        }
    }

    /* Actions to make then_rsc gain then_role */
    if (then_role == pcmk_role_promoted) {
        then_tasks[0] = PCMK_ACTION_PROMOTE;

    } else {
        then_tasks[0] = PCMK_ACTION_START;

        if (then_role == pcmk_role_unpromoted) {
            then_tasks[1] = PCMK_ACTION_DEMOTE;
        }
    }

    for (int first_lpc = 0;
         (first_lpc <= 1) && (first_tasks[first_lpc] != NULL); first_lpc++) {

        for (int then_lpc = 0;
             (then_lpc <= 1) && (then_tasks[then_lpc] != NULL); then_lpc++) {

            pcmk__order_resource_actions(first_rsc, first_tasks[first_lpc],
                                         then_rsc, then_tasks[then_lpc],
                                         pcmk__ar_if_required_on_same_node);
        }
    }
}

/*!
 * \internal
 * \brief Add a new colocation constraint to scheduler data
 *
 * \param[in]     id              XML ID for this constraint
 * \param[in]     node_attr       Colocate by this attribute (NULL for #uname)
 * \param[in]     score           Constraint score
 * \param[in,out] dependent       Resource to be colocated
 * \param[in,out] primary         Resource to colocate \p dependent with
 * \param[in]     dependent_role_spec  If not NULL, only \p dependent instances
 *                                     with this role should be colocated
 * \param[in]     primary_role_spec    If not NULL, only \p primary instances
 *                                     with this role should be colocated
 * \param[in]     flags           Group of enum pcmk__coloc_flags
 */
void
pcmk__new_colocation(const char *id, const char *node_attr, int score,
                     pcmk_resource_t *dependent, pcmk_resource_t *primary,
                     const char *dependent_role_spec,
                     const char *primary_role_spec, uint32_t flags)
{
    pcmk__colocation_t *new_con = NULL;
    enum rsc_role_e dependent_role = pcmk_role_unknown;
    enum rsc_role_e primary_role = pcmk_role_unknown;

    CRM_CHECK(id != NULL, return);

    if ((dependent == NULL) || (primary == NULL)) {
        pcmk__config_err("Ignoring colocation '%s' because resource "
                         "does not exist", id);
        return;
    }
    if ((pcmk__parse_constraint_role(id, dependent_role_spec,
                                     &dependent_role) != pcmk_rc_ok)
        || (pcmk__parse_constraint_role(id, primary_role_spec,
                                        &primary_role) != pcmk_rc_ok)) {
        // Not possible with schema validation enabled (error already logged)
        return;
    }

    if (score == 0) {
        pcmk__rsc_trace(dependent,
                        "Ignoring colocation '%s' (%s with %s) because score is 0",
                        id, dependent->id, primary->id);
        return;
    }

    new_con = pcmk__assert_alloc(1, sizeof(pcmk__colocation_t));
    new_con->id = id;
    new_con->dependent = dependent;
    new_con->primary = primary;
    new_con->score = score;
    new_con->dependent_role = dependent_role;
    new_con->primary_role = primary_role;

    new_con->node_attribute = pcmk__s(node_attr, CRM_ATTR_UNAME);
    new_con->flags = flags;

    pcmk__add_this_with(&(dependent->priv->this_with_colocations), new_con,
                        dependent);
    pcmk__add_with_this(&(primary->priv->with_this_colocations), new_con,
                        primary);

    dependent->priv->scheduler->priv->colocation_constraints =
        g_list_prepend(dependent->priv->scheduler->priv->colocation_constraints,
                       new_con);

    if (score <= -PCMK_SCORE_INFINITY) {
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
 * \param[in] influence_s  String value of \c PCMK_XA_INFLUENCE option
 *
 * \return \c pcmk__coloc_influence if string evaluates true, or string is
 *         \c NULL or invalid and resource's \c PCMK_META_CRITICAL option
 *         evaluates true, otherwise \c pcmk__coloc_none
 */
static uint32_t
unpack_influence(const char *coloc_id, const pcmk_resource_t *rsc,
                 const char *influence_s)
{
    if (influence_s != NULL) {
        int influence_i = 0;

        if (crm_str_to_boolean(influence_s, &influence_i) < 0) {
            pcmk__config_err("Constraint '%s' has invalid value for "
                             PCMK_XA_INFLUENCE " (using default)",
                             coloc_id);
        } else {
            return (influence_i == 0)? pcmk__coloc_none : pcmk__coloc_influence;
        }
    }
    if (pcmk_is_set(rsc->flags, pcmk__rsc_critical)) {
        return pcmk__coloc_influence;
    }
    return pcmk__coloc_none;
}

static void
unpack_colocation_set(xmlNode *set, int score, const char *coloc_id,
                      const char *influence_s, pcmk_scheduler_t *scheduler)
{
    xmlNode *xml_rsc = NULL;
    pcmk_resource_t *other = NULL;
    pcmk_resource_t *resource = NULL;
    const char *set_id = pcmk__xe_id(set);
    const char *role = crm_element_value(set, PCMK_XA_ROLE);
    bool with_previous = false;
    int local_score = score;
    bool sequential = false;
    uint32_t flags = pcmk__coloc_none;
    const char *xml_rsc_id = NULL;
    const char *score_s = crm_element_value(set, PCMK_XA_SCORE);

    if (score_s != NULL) {
        int rc = pcmk_parse_score(score_s, &local_score, 0);

        if (rc != pcmk_rc_ok) { // Not possible with schema validation enabled
            pcmk__config_err("Ignoring colocation '%s' for set '%s' "
                             "because '%s' is not a valid score",
                             coloc_id, set_id, score_s);
            return;
        }
    }
    if (local_score == 0) {
        crm_trace("Ignoring colocation '%s' for set '%s' because score is 0",
                  coloc_id, set_id);
        return;
    }

    /* @COMPAT The deprecated PCMK__XA_ORDERING attribute specifies whether
     * resources in a positive-score set are colocated with the previous or next
     * resource.
     */
    if (pcmk__str_eq(crm_element_value(set, PCMK__XA_ORDERING),
                     PCMK__VALUE_GROUP,
                     pcmk__str_null_matches|pcmk__str_casei)) {
        with_previous = true;
    } else {
        pcmk__warn_once(pcmk__wo_set_ordering,
                        "Support for '" PCMK__XA_ORDERING "' other than"
                        " '" PCMK__VALUE_GROUP "' in " PCMK_XE_RESOURCE_SET
                        " (such as %s) is deprecated and will be removed in a"
                        " future release",
                        set_id);
    }

    if ((pcmk__xe_get_bool_attr(set, PCMK_XA_SEQUENTIAL,
                                &sequential) == pcmk_rc_ok)
        && !sequential) {
        return;
    }

    if (local_score > 0) {
        for (xml_rsc = pcmk__xe_first_child(set, PCMK_XE_RESOURCE_REF, NULL,
                                            NULL);
             xml_rsc != NULL;
             xml_rsc = pcmk__xe_next(xml_rsc, PCMK_XE_RESOURCE_REF)) {

            xml_rsc_id = pcmk__xe_id(xml_rsc);
            resource =
                pcmk__find_constraint_resource(scheduler->priv->resources,
                                               xml_rsc_id);
            if (resource == NULL) {
                // Should be possible only with validation disabled
                pcmk__config_err("Ignoring %s and later resources in set %s: "
                                 "No such resource", xml_rsc_id, set_id);
                return;
            }
            if (other != NULL) {
                flags = pcmk__coloc_explicit
                        | unpack_influence(coloc_id, resource, influence_s);
                if (with_previous) {
                    pcmk__rsc_trace(resource, "Colocating %s with %s in set %s",
                                    resource->id, other->id, set_id);
                    pcmk__new_colocation(set_id, NULL, local_score, resource,
                                         other, role, role, flags);
                } else {
                    pcmk__rsc_trace(resource, "Colocating %s with %s in set %s",
                                    other->id, resource->id, set_id);
                    pcmk__new_colocation(set_id, NULL, local_score, other,
                                         resource, role, role, flags);
                }
            }
            other = resource;
        }

    } else {
        /* Anti-colocating with every prior resource is
         * the only way to ensure the intuitive result
         * (i.e. that no one in the set can run with anyone else in the set)
         */

        for (xml_rsc = pcmk__xe_first_child(set, PCMK_XE_RESOURCE_REF, NULL,
                                            NULL);
             xml_rsc != NULL;
             xml_rsc = pcmk__xe_next(xml_rsc, PCMK_XE_RESOURCE_REF)) {

            xmlNode *xml_rsc_with = NULL;

            xml_rsc_id = pcmk__xe_id(xml_rsc);
            resource =
                pcmk__find_constraint_resource(scheduler->priv->resources,
                                               xml_rsc_id);
            if (resource == NULL) {
                // Should be possible only with validation disabled
                pcmk__config_err("Ignoring %s and later resources in set %s: "
                                 "No such resource", xml_rsc_id, set_id);
                return;
            }
            flags = pcmk__coloc_explicit
                    | unpack_influence(coloc_id, resource, influence_s);
            for (xml_rsc_with = pcmk__xe_first_child(set, PCMK_XE_RESOURCE_REF,
                                                     NULL, NULL);
                 xml_rsc_with != NULL;
                 xml_rsc_with = pcmk__xe_next(xml_rsc_with,
                                              PCMK_XE_RESOURCE_REF)) {

                xml_rsc_id = pcmk__xe_id(xml_rsc_with);
                if (pcmk__str_eq(resource->id, xml_rsc_id, pcmk__str_none)) {
                    break;
                }
                other =
                    pcmk__find_constraint_resource(scheduler->priv->resources,
                                                   xml_rsc_id);
                pcmk__assert(other != NULL); // We already processed it
                pcmk__new_colocation(set_id, NULL, local_score,
                                     resource, other, role, role, flags);
            }
        }
    }
}

/*!
 * \internal
 * \brief Colocate two resource sets relative to each other
 *
 * \param[in]     id           Colocation XML ID
 * \param[in]     set1         Dependent set
 * \param[in]     set2         Primary set
 * \param[in]     score        Colocation score
 * \param[in]     influence_s  Value of colocation's \c PCMK_XA_INFLUENCE
 *                             attribute
 * \param[in,out] scheduler    Scheduler data
 */
static void
colocate_rsc_sets(const char *id, const xmlNode *set1, const xmlNode *set2,
                  int score, const char *influence_s,
                  pcmk_scheduler_t *scheduler)
{
    xmlNode *xml_rsc = NULL;
    pcmk_resource_t *rsc_1 = NULL;
    pcmk_resource_t *rsc_2 = NULL;

    const char *xml_rsc_id = NULL;
    const char *role_1 = crm_element_value(set1, PCMK_XA_ROLE);
    const char *role_2 = crm_element_value(set2, PCMK_XA_ROLE);

    int rc = pcmk_rc_ok;
    bool sequential = false;
    uint32_t flags = pcmk__coloc_none;

    if (score == 0) {
        crm_trace("Ignoring colocation '%s' between sets %s and %s "
                  "because score is 0",
                  id, pcmk__xe_id(set1), pcmk__xe_id(set2));
        return;
    }

    rc = pcmk__xe_get_bool_attr(set1, PCMK_XA_SEQUENTIAL, &sequential);
    if ((rc != pcmk_rc_ok) || sequential) {
        // Get the first one
        xml_rsc = pcmk__xe_first_child(set1, PCMK_XE_RESOURCE_REF, NULL, NULL);
        if (xml_rsc != NULL) {
            xml_rsc_id = pcmk__xe_id(xml_rsc);
            rsc_1 = pcmk__find_constraint_resource(scheduler->priv->resources,
                                                   xml_rsc_id);
            if (rsc_1 == NULL) {
                // Should be possible only with validation disabled
                pcmk__config_err("Ignoring colocation of set %s with set %s "
                                 "because first resource %s not found",
                                 pcmk__xe_id(set1), pcmk__xe_id(set2),
                                 xml_rsc_id);
                return;
            }
        }
    }

    rc = pcmk__xe_get_bool_attr(set2, PCMK_XA_SEQUENTIAL, &sequential);
    if ((rc != pcmk_rc_ok) || sequential) {
        // Get the last one
        for (xml_rsc = pcmk__xe_first_child(set2, PCMK_XE_RESOURCE_REF, NULL,
                                            NULL);
             xml_rsc != NULL;
             xml_rsc = pcmk__xe_next(xml_rsc, PCMK_XE_RESOURCE_REF)) {

            xml_rsc_id = pcmk__xe_id(xml_rsc);
        }
        rsc_2 = pcmk__find_constraint_resource(scheduler->priv->resources,
                                               xml_rsc_id);
        if (rsc_2 == NULL) {
            // Should be possible only with validation disabled
            pcmk__config_err("Ignoring colocation of set %s with set %s "
                             "because last resource %s not found",
                             pcmk__xe_id(set1), pcmk__xe_id(set2), xml_rsc_id);
            return;
        }
    }

    if ((rsc_1 != NULL) && (rsc_2 != NULL)) { // Both sets are sequential
        flags = pcmk__coloc_explicit | unpack_influence(id, rsc_1, influence_s);
        pcmk__new_colocation(id, NULL, score, rsc_1, rsc_2, role_1, role_2,
                             flags);

    } else if (rsc_1 != NULL) { // Only set1 is sequential
        flags = pcmk__coloc_explicit | unpack_influence(id, rsc_1, influence_s);
        for (xml_rsc = pcmk__xe_first_child(set2, PCMK_XE_RESOURCE_REF, NULL,
                                            NULL);
             xml_rsc != NULL;
             xml_rsc = pcmk__xe_next(xml_rsc, PCMK_XE_RESOURCE_REF)) {

            xml_rsc_id = pcmk__xe_id(xml_rsc);
            rsc_2 = pcmk__find_constraint_resource(scheduler->priv->resources,
                                                   xml_rsc_id);
            if (rsc_2 == NULL) {
                // Should be possible only with validation disabled
                pcmk__config_err("Ignoring set %s colocation with resource %s "
                                 "in set %s: No such resource",
                                 pcmk__xe_id(set1), xml_rsc_id,
                                 pcmk__xe_id(set2));
                continue;
            }
            pcmk__new_colocation(id, NULL, score, rsc_1, rsc_2, role_1,
                                 role_2, flags);
        }

    } else if (rsc_2 != NULL) { // Only set2 is sequential
        for (xml_rsc = pcmk__xe_first_child(set1, PCMK_XE_RESOURCE_REF, NULL,
                                            NULL);
             xml_rsc != NULL;
             xml_rsc = pcmk__xe_next(xml_rsc, PCMK_XE_RESOURCE_REF)) {

            xml_rsc_id = pcmk__xe_id(xml_rsc);
            rsc_1 = pcmk__find_constraint_resource(scheduler->priv->resources,
                                                   xml_rsc_id);
            if (rsc_1 == NULL) {
                // Should be possible only with validation disabled
                pcmk__config_err("Ignoring colocation of set %s resource %s "
                                 "with set %s: No such resource",
                                 pcmk__xe_id(set1), xml_rsc_id,
                                 pcmk__xe_id(set2));
                continue;
            }
            flags = pcmk__coloc_explicit
                    | unpack_influence(id, rsc_1, influence_s);
            pcmk__new_colocation(id, NULL, score, rsc_1, rsc_2, role_1,
                                 role_2, flags);
        }

    } else { // Neither set is sequential
        for (xml_rsc = pcmk__xe_first_child(set1, PCMK_XE_RESOURCE_REF, NULL,
                                            NULL);
             xml_rsc != NULL;
             xml_rsc = pcmk__xe_next(xml_rsc, PCMK_XE_RESOURCE_REF)) {

            xmlNode *xml_rsc_2 = NULL;

            xml_rsc_id = pcmk__xe_id(xml_rsc);
            rsc_1 = pcmk__find_constraint_resource(scheduler->priv->resources,
                                                   xml_rsc_id);
            if (rsc_1 == NULL) {
                // Should be possible only with validation disabled
                pcmk__config_err("Ignoring colocation of set %s resource %s "
                                 "with set %s: No such resource",
                                 pcmk__xe_id(set1), xml_rsc_id,
                                 pcmk__xe_id(set2));
                continue;
            }

            flags = pcmk__coloc_explicit
                    | unpack_influence(id, rsc_1, influence_s);
            for (xml_rsc_2 = pcmk__xe_first_child(set2, PCMK_XE_RESOURCE_REF,
                                                  NULL, NULL);
                 xml_rsc_2 != NULL;
                 xml_rsc_2 = pcmk__xe_next(xml_rsc_2, PCMK_XE_RESOURCE_REF)) {

                xml_rsc_id = pcmk__xe_id(xml_rsc_2);
                rsc_2 =
                    pcmk__find_constraint_resource(scheduler->priv->resources,
                                                   xml_rsc_id);
                if (rsc_2 == NULL) {
                    // Should be possible only with validation disabled
                    pcmk__config_err("Ignoring colocation of set %s resource "
                                     "%s with set %s resource %s: No such "
                                     "resource",
                                     pcmk__xe_id(set1), pcmk__xe_id(xml_rsc),
                                     pcmk__xe_id(set2), xml_rsc_id);
                    continue;
                }
                pcmk__new_colocation(id, NULL, score, rsc_1, rsc_2,
                                     role_1, role_2, flags);
            }
        }
    }
}

/*!
 * \internal
 * \brief Unpack a colocation constraint that contains no resource sets
 *
 * \param[in]     xml_obj      Colocation constraint XML
 * \param[in]     id           Colocation constraint XML ID (non-NULL)
 * \param[in]     score        Integer score parsed from score attribute
 * \param[in]     influence_s  Colocation constraint's influence attribute value
 * \param[in,out] scheduler    Scheduler data
 */
static void
unpack_simple_colocation(const xmlNode *xml_obj, const char *id, int score,
                         const char *influence_s, pcmk_scheduler_t *scheduler)
{
    uint32_t flags = pcmk__coloc_none;

    const char *dependent_id = crm_element_value(xml_obj, PCMK_XA_RSC);
    const char *primary_id = crm_element_value(xml_obj, PCMK_XA_WITH_RSC);
    const char *dependent_role = crm_element_value(xml_obj, PCMK_XA_RSC_ROLE);
    const char *primary_role = crm_element_value(xml_obj,
                                                 PCMK_XA_WITH_RSC_ROLE);
    const char *attr = crm_element_value(xml_obj, PCMK_XA_NODE_ATTRIBUTE);

    pcmk_resource_t *primary = NULL;
    pcmk_resource_t *dependent = NULL;

    primary = pcmk__find_constraint_resource(scheduler->priv->resources,
                                             primary_id);
    dependent = pcmk__find_constraint_resource(scheduler->priv->resources,
                                               dependent_id);

    if (dependent == NULL) {
        pcmk__config_err("Ignoring constraint '%s' because resource '%s' "
                         "does not exist", id, dependent_id);
        return;

    } else if (primary == NULL) {
        pcmk__config_err("Ignoring constraint '%s' because resource '%s' "
                         "does not exist", id, primary_id);
        return;
    }

    if (pcmk__xe_attr_is_true(xml_obj, PCMK_XA_SYMMETRICAL)) {
        pcmk__config_warn("The colocation constraint "
                          "'" PCMK_XA_SYMMETRICAL "' attribute has been "
                          "removed");
    }

    flags = pcmk__coloc_explicit | unpack_influence(id, dependent, influence_s);
    pcmk__new_colocation(id, attr, score, dependent, primary,
                         dependent_role, primary_role, flags);
}

// \return Standard Pacemaker return code
static int
unpack_colocation_tags(xmlNode *xml_obj, xmlNode **expanded_xml,
                       pcmk_scheduler_t *scheduler)
{
    const char *id = NULL;
    const char *dependent_id = NULL;
    const char *primary_id = NULL;
    const char *dependent_role = NULL;
    const char *primary_role = NULL;

    pcmk_resource_t *dependent = NULL;
    pcmk_resource_t *primary = NULL;

    pcmk__idref_t *dependent_tag = NULL;
    pcmk__idref_t *primary_tag = NULL;

    xmlNode *dependent_set = NULL;
    xmlNode *primary_set = NULL;
    bool any_sets = false;

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
        crm_log_xml_trace(*expanded_xml, "Expanded " PCMK_XE_RSC_COLOCATION);
        return pcmk_rc_ok;
    }

    dependent_id = crm_element_value(xml_obj, PCMK_XA_RSC);
    primary_id = crm_element_value(xml_obj, PCMK_XA_WITH_RSC);
    if ((dependent_id == NULL) || (primary_id == NULL)) {
        return pcmk_rc_ok;
    }

    if (!pcmk__valid_resource_or_tag(scheduler, dependent_id, &dependent,
                                     &dependent_tag)) {
        pcmk__config_err("Ignoring constraint '%s' because '%s' is not a "
                         "valid resource or tag", id, dependent_id);
        return pcmk_rc_unpack_error;
    }

    if (!pcmk__valid_resource_or_tag(scheduler, primary_id, &primary,
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

    dependent_role = crm_element_value(xml_obj, PCMK_XA_RSC_ROLE);
    primary_role = crm_element_value(xml_obj, PCMK_XA_WITH_RSC_ROLE);

    *expanded_xml = pcmk__xml_copy(NULL, xml_obj);

    /* Convert dependent's template/tag reference into constraint
     * PCMK_XE_RESOURCE_SET
     */
    if (!pcmk__tag_to_set(*expanded_xml, &dependent_set, PCMK_XA_RSC, true,
                          scheduler)) {
        pcmk__xml_free(*expanded_xml);
        *expanded_xml = NULL;
        return pcmk_rc_unpack_error;
    }

    if (dependent_set != NULL) {
        if (dependent_role != NULL) {
            /* Move PCMK_XA_RSC_ROLE into converted PCMK_XE_RESOURCE_SET as
             * PCMK_XA_ROLE
             */
            crm_xml_add(dependent_set, PCMK_XA_ROLE, dependent_role);
            pcmk__xe_remove_attr(*expanded_xml, PCMK_XA_RSC_ROLE);
        }
        any_sets = true;
    }

    /* Convert primary's template/tag reference into constraint
     * PCMK_XE_RESOURCE_SET
     */
    if (!pcmk__tag_to_set(*expanded_xml, &primary_set, PCMK_XA_WITH_RSC, true,
                          scheduler)) {
        pcmk__xml_free(*expanded_xml);
        *expanded_xml = NULL;
        return pcmk_rc_unpack_error;
    }

    if (primary_set != NULL) {
        if (primary_role != NULL) {
            /* Move PCMK_XA_WITH_RSC_ROLE into converted PCMK_XE_RESOURCE_SET as
             * PCMK_XA_ROLE
             */
            crm_xml_add(primary_set, PCMK_XA_ROLE, primary_role);
            pcmk__xe_remove_attr(*expanded_xml, PCMK_XA_WITH_RSC_ROLE);
        }
        any_sets = true;
    }

    if (any_sets) {
        crm_log_xml_trace(*expanded_xml, "Expanded " PCMK_XE_RSC_COLOCATION);
    } else {
        pcmk__xml_free(*expanded_xml);
        *expanded_xml = NULL;
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Parse a colocation constraint from XML into scheduler data
 *
 * \param[in,out] xml_obj    Colocation constraint XML to unpack
 * \param[in,out] scheduler  Scheduler data to add constraint to
 */
void
pcmk__unpack_colocation(xmlNode *xml_obj, pcmk_scheduler_t *scheduler)
{
    int score_i = 0;
    xmlNode *set = NULL;
    xmlNode *last = NULL;

    xmlNode *orig_xml = NULL;
    xmlNode *expanded_xml = NULL;

    const char *id = crm_element_value(xml_obj, PCMK_XA_ID);
    const char *score = NULL;
    const char *influence_s = NULL;

    if (pcmk__str_empty(id)) {
        pcmk__config_err("Ignoring " PCMK_XE_RSC_COLOCATION
                         " without " CRM_ATTR_ID);
        return;
    }

    if (unpack_colocation_tags(xml_obj, &expanded_xml,
                               scheduler) != pcmk_rc_ok) {
        return;
    }
    if (expanded_xml != NULL) {
        orig_xml = xml_obj;
        xml_obj = expanded_xml;
    }

    score = crm_element_value(xml_obj, PCMK_XA_SCORE);
    if (score != NULL) {
        int rc = pcmk_parse_score(score, &score_i, 0);

        if (rc != pcmk_rc_ok) { // Not possible with schema validation enabled
            pcmk__config_err("Ignoring colocation %s because '%s' "
                             "is not a valid score", id, score);
            return;
        }
    }
    influence_s = crm_element_value(xml_obj, PCMK_XA_INFLUENCE);

    for (set = pcmk__xe_first_child(xml_obj, PCMK_XE_RESOURCE_SET, NULL, NULL);
         set != NULL; set = pcmk__xe_next(set, PCMK_XE_RESOURCE_SET)) {

        set = pcmk__xe_resolve_idref(set, scheduler->input);
        if (set == NULL) { // Configuration error, message already logged
            if (expanded_xml != NULL) {
                pcmk__xml_free(expanded_xml);
            }
            return;
        }

        if (pcmk__str_empty(pcmk__xe_id(set))) {
            pcmk__config_err("Ignoring " PCMK_XE_RESOURCE_SET
                             " without " CRM_ATTR_ID);
            continue;
        }
        unpack_colocation_set(set, score_i, id, influence_s, scheduler);

        if (last != NULL) {
            colocate_rsc_sets(id, last, set, score_i, influence_s, scheduler);
        }
        last = set;
    }

    if (expanded_xml) {
        pcmk__xml_free(expanded_xml);
        xml_obj = orig_xml;
    }

    if (last == NULL) {
        unpack_simple_colocation(xml_obj, id, score_i, influence_s, scheduler);
    }
}

/*!
 * \internal
 * \brief Check whether colocation's dependent preferences should be considered
 *
 * \param[in] colocation  Colocation constraint
 * \param[in] rsc         Primary instance (normally this will be
 *                        colocation->primary, which NULL will be treated as,
 *                        but for clones or bundles with multiple instances
 *                        this can be a particular instance)
 *
 * \return true if colocation influence should be effective, otherwise false
 */
bool
pcmk__colocation_has_influence(const pcmk__colocation_t *colocation,
                               const pcmk_resource_t *rsc)
{
    if (rsc == NULL) {
        rsc = colocation->primary;
    }

    /* A bundle replica colocates its remote connection with its container,
     * using a finite score so that the container can run on Pacemaker Remote
     * nodes.
     *
     * Moving a connection is lightweight and does not interrupt the service,
     * while moving a container is heavyweight and does interrupt the service,
     * so don't move a clean, active container based solely on the preferences
     * of its connection.
     *
     * This also avoids problematic scenarios where two containers want to
     * perpetually swap places.
     */
    if (pcmk_is_set(colocation->dependent->flags,
                    pcmk__rsc_remote_nesting_allowed)
        && !pcmk_is_set(rsc->flags, pcmk__rsc_failed)
        && pcmk__list_of_1(rsc->priv->active_nodes)) {
        return false;
    }

    /* The dependent in a colocation influences the primary's location
     * if the PCMK_XA_INFLUENCE option is true or the primary is not yet active.
     */
    return pcmk_is_set(colocation->flags, pcmk__coloc_influence)
           || (rsc->priv->active_nodes == NULL);
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
mark_action_blocked(pcmk_resource_t *rsc, const char *task,
                    const pcmk_resource_t *reason)
{
    GList *iter = NULL;
    char *reason_text = crm_strdup_printf("colocation with %s", reason->id);

    for (iter = rsc->priv->actions; iter != NULL; iter = iter->next) {
        pcmk_action_t *action = iter->data;

        if (pcmk_is_set(action->flags, pcmk__action_runnable)
            && pcmk__str_eq(action->task, task, pcmk__str_none)) {

            pcmk__clear_action_flags(action, pcmk__action_runnable);
            pe_action_set_reason(action, reason_text, false);
            pcmk__block_colocation_dependents(action);
            pcmk__update_action_for_orderings(action, rsc->priv->scheduler);
        }
    }

    // If parent resource can't perform an action, neither can any children
    for (iter = rsc->priv->children; iter != NULL; iter = iter->next) {
        mark_action_blocked((pcmk_resource_t *) (iter->data), task, reason);
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
 * \param[in,out] action  Action to check
 */
void
pcmk__block_colocation_dependents(pcmk_action_t *action)
{
    GList *iter = NULL;
    GList *colocations = NULL;
    pcmk_resource_t *rsc = NULL;
    bool is_start = false;

    if (pcmk_is_set(action->flags, pcmk__action_runnable)) {
        return; // Only unrunnable actions block dependents
    }

    is_start = pcmk__str_eq(action->task, PCMK_ACTION_START, pcmk__str_none);
    if (!is_start
        && !pcmk__str_eq(action->task, PCMK_ACTION_PROMOTE, pcmk__str_none)) {
        return; // Only unrunnable starts and promotes block dependents
    }

    pcmk__assert(action->rsc != NULL); // Start and promote are resource actions

    /* If this resource is part of a collective resource, dependents are blocked
     * only if all instances of the collective are unrunnable, so check the
     * collective resource.
     */
    rsc = uber_parent(action->rsc);
    if (rsc->priv->parent != NULL) {
        rsc = rsc->priv->parent; // Bundle
    }

    // Colocation fails only if entire primary can't reach desired role
    for (iter = rsc->priv->children; iter != NULL; iter = iter->next) {
        pcmk_resource_t *child = iter->data;
        pcmk_action_t *child_action = NULL;

        child_action = find_first_action(child->priv->actions, NULL,
                                         action->task, NULL);
        if ((child_action == NULL)
            || pcmk_is_set(child_action->flags, pcmk__action_runnable)) {
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
    for (iter = colocations; iter != NULL; iter = iter->next) {
        pcmk__colocation_t *colocation = iter->data;

        if (colocation->score < PCMK_SCORE_INFINITY) {
            continue; // Only mandatory colocations block dependent
        }

        /* If the primary can't start, the dependent can't reach its colocated
         * role, regardless of what the primary or dependent colocation role is.
         *
         * If the primary can't be promoted, the dependent can't reach its
         * colocated role if the primary's colocation role is promoted.
         */
        if (!is_start && (colocation->primary_role != pcmk_role_promoted)) {
            continue;
        }

        // Block the dependent from reaching its colocated role
        if (colocation->dependent_role == pcmk_role_promoted) {
            mark_action_blocked(colocation->dependent, PCMK_ACTION_PROMOTE,
                                action->rsc);
        } else {
            mark_action_blocked(colocation->dependent, PCMK_ACTION_START,
                                action->rsc);
        }
    }
    g_list_free(colocations);
}

/*!
 * \internal
 * \brief Get the resource to use for role comparisons
 *
 * A bundle replica includes a container and possibly an instance of the bundled
 * resource. The dependent in a "with bundle" colocation is colocated with a
 * particular bundle container. However, if the colocation includes a role, then
 * the role must be checked on the bundled resource instance inside the
 * container. The container itself will never be promoted; the bundled resource
 * may be.
 *
 * If the given resource is a bundle replica container, return the resource
 * inside it, if any. Otherwise, return the resource itself.
 *
 * \param[in] rsc  Resource to check
 *
 * \return Resource to use for role comparisons
 */
static const pcmk_resource_t *
get_resource_for_role(const pcmk_resource_t *rsc)
{
    if (pcmk_is_set(rsc->flags, pcmk__rsc_replica_container)) {
        const pcmk_resource_t *child = pe__get_rsc_in_container(rsc);

        if (child != NULL) {
            return child;
        }
    }
    return rsc;
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
 * \param[in] preview     If true, pretend resources have already been assigned
 *
 * \return How colocation constraint should be applied at this point
 */
enum pcmk__coloc_affects
pcmk__colocation_affects(const pcmk_resource_t *dependent,
                         const pcmk_resource_t *primary,
                         const pcmk__colocation_t *colocation, bool preview)
{
    const pcmk_resource_t *dependent_role_rsc = NULL;
    const pcmk_resource_t *primary_role_rsc = NULL;

    pcmk__assert((dependent != NULL) && (primary != NULL)
                 && (colocation != NULL));

    if (!preview && pcmk_is_set(primary->flags, pcmk__rsc_unassigned)) {
        // Primary resource has not been assigned yet, so we can't do anything
        return pcmk__coloc_affects_nothing;
    }

    dependent_role_rsc = get_resource_for_role(dependent);

    primary_role_rsc = get_resource_for_role(primary);

    if ((colocation->dependent_role >= pcmk_role_unpromoted)
        && (dependent_role_rsc->priv->parent != NULL)
        && pcmk_is_set(dependent_role_rsc->priv->parent->flags,
                       pcmk__rsc_promotable)
        && !pcmk_is_set(dependent_role_rsc->flags, pcmk__rsc_unassigned)) {

        /* This is a colocation by role, and the dependent is a promotable clone
         * that has already been assigned, so the colocation should now affect
         * the role.
         */
        return pcmk__coloc_affects_role;
    }

    if (!preview && !pcmk_is_set(dependent->flags, pcmk__rsc_unassigned)) {
        /* The dependent resource has already been through assignment, so the
         * constraint no longer matters.
         */
        return pcmk__coloc_affects_nothing;
    }

    if ((colocation->dependent_role != pcmk_role_unknown)
        && (colocation->dependent_role != dependent_role_rsc->priv->next_role)) {
        crm_trace("Skipping %scolocation '%s': dependent limited to %s role "

                  "but %s next role is %s",
                  ((colocation->score < 0)? "anti-" : ""),
                  colocation->id, pcmk_role_text(colocation->dependent_role),
                  dependent_role_rsc->id,
                  pcmk_role_text(dependent_role_rsc->priv->next_role));
        return pcmk__coloc_affects_nothing;
    }

    if ((colocation->primary_role != pcmk_role_unknown)
        && (colocation->primary_role != primary_role_rsc->priv->next_role)) {
        crm_trace("Skipping %scolocation '%s': primary limited to %s role "
                  "but %s next role is %s",
                  ((colocation->score < 0)? "anti-" : ""),
                  colocation->id, pcmk_role_text(colocation->primary_role),
                  primary_role_rsc->id,
                  pcmk_role_text(primary_role_rsc->priv->next_role));
        return pcmk__coloc_affects_nothing;
    }

    return pcmk__coloc_affects_location;
}

/*!
 * \internal
 * \brief Apply colocation to dependent for assignment purposes
 *
 * Update the allowed node scores of the dependent resource in a colocation,
 * for the purposes of assigning it to a node.
 *
 * \param[in,out] dependent   Dependent resource in colocation
 * \param[in]     primary     Primary resource in colocation
 * \param[in]     colocation  Colocation constraint
 */
void
pcmk__apply_coloc_to_scores(pcmk_resource_t *dependent,
                            const pcmk_resource_t *primary,
                            const pcmk__colocation_t *colocation)
{
    const char *attr = colocation->node_attribute;
    const char *value = NULL;
    GHashTable *work = NULL;
    GHashTableIter iter;
    pcmk_node_t *node = NULL;

    if (primary->priv->assigned_node != NULL) {
        value = pcmk__colocation_node_attr(primary->priv->assigned_node,
                                           attr, primary);

    } else if (colocation->score < 0) {
        // Nothing to do (anti-colocation with something that is not running)
        return;
    }

    work = pcmk__copy_node_table(dependent->priv->allowed_nodes);

    g_hash_table_iter_init(&iter, work);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
        if (primary->priv->assigned_node == NULL) {
            node->assign->score = pcmk__add_scores(-colocation->score,
                                                   node->assign->score);
            pcmk__rsc_trace(dependent,
                            "Applied %s to %s score on %s (now %s after "
                            "subtracting %s because primary %s inactive)",
                            colocation->id, dependent->id,
                            pcmk__node_name(node),
                            pcmk_readable_score(node->assign->score),
                            pcmk_readable_score(colocation->score), primary->id);
            continue;
        }

        if (pcmk__str_eq(pcmk__colocation_node_attr(node, attr, dependent),
                         value, pcmk__str_casei)) {

            /* Add colocation score only if optional (or minus infinity). A
             * mandatory colocation is a requirement rather than a preference,
             * so we don't need to consider it for relative assignment purposes.
             * The resource will simply be forbidden from running on the node if
             * the primary isn't active there (via the condition above).
             */
            if (colocation->score < PCMK_SCORE_INFINITY) {
                node->assign->score = pcmk__add_scores(colocation->score,
                                                       node->assign->score);
                pcmk__rsc_trace(dependent,
                                "Applied %s to %s score on %s (now %s after "
                                "adding %s)",
                                colocation->id, dependent->id,
                                pcmk__node_name(node),
                                pcmk_readable_score(node->assign->score),
                                pcmk_readable_score(colocation->score));
            }
            continue;
        }

        if (colocation->score >= PCMK_SCORE_INFINITY) {
            /* Only mandatory colocations are relevant when the colocation
             * attribute doesn't match, because an attribute not matching is not
             * a negative preference -- the colocation is simply relevant only
             * where it matches.
             */
            node->assign->score = -PCMK_SCORE_INFINITY;
            pcmk__rsc_trace(dependent,
                            "Banned %s from %s because colocation %s attribute %s "
                            "does not match",
                            dependent->id, pcmk__node_name(node),
                            colocation->id, attr);
        }
    }

    if ((colocation->score <= -PCMK_SCORE_INFINITY)
        || (colocation->score >= PCMK_SCORE_INFINITY)
        || pcmk__any_node_available(work, pcmk__node_alive
                                          |pcmk__node_usable
                                          |pcmk__node_no_negative)) {

        g_hash_table_destroy(dependent->priv->allowed_nodes);
        dependent->priv->allowed_nodes = work;
        work = NULL;

    } else {
        pcmk__rsc_info(dependent,
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
 *
 * \return The score added to the dependent's priority
 */
int
pcmk__apply_coloc_to_priority(pcmk_resource_t *dependent,
                              const pcmk_resource_t *primary,
                              const pcmk__colocation_t *colocation)
{
    const char *dependent_value = NULL;
    const char *primary_value = NULL;
    const char *attr = colocation->node_attribute;
    int score_multiplier = 1;
    int priority_delta = 0;
    const pcmk_node_t *primary_node = NULL;
    const pcmk_node_t *dependent_node = NULL;

    pcmk__assert((dependent != NULL) && (primary != NULL)
                 && (colocation != NULL));

    primary_node = primary->priv->assigned_node;
    dependent_node = dependent->priv->assigned_node;

    if (dependent_node == NULL) {
        return 0;
    }

    if ((primary_node != NULL)
        && (colocation->primary_role != pcmk_role_unknown)) {
        /* Colocation applies only if the primary's next role matches.
         *
         * If primary_node == NULL, we want to proceed past this block, so that
         * dependent_node is marked ineligible for promotion.
         *
         * @TODO Why ignore a mandatory colocation in this case when we apply
         * its negation in the mismatched value case?
         */
        const pcmk_resource_t *role_rsc = get_resource_for_role(primary);

        if (colocation->primary_role != role_rsc->priv->next_role) {
            return 0;
        }
    }

    dependent_value = pcmk__colocation_node_attr(dependent_node, attr,
                                                 dependent);
    primary_value = pcmk__colocation_node_attr(primary_node, attr, primary);

    if (!pcmk__str_eq(dependent_value, primary_value, pcmk__str_casei)) {
        if ((colocation->score == PCMK_SCORE_INFINITY)
            && (colocation->dependent_role == pcmk_role_promoted)) {
            /* For a mandatory promoted-role colocation, mark the dependent node
             * ineligible to promote the dependent if its attribute value
             * doesn't match the primary node's
             */
            score_multiplier = -1;

        } else {
            // Otherwise, ignore the colocation if attribute values don't match
            return 0;
        }

    } else if (colocation->dependent_role == pcmk_role_unpromoted) {
        /* Node attribute values matched, so we want to avoid promoting the
         * dependent on this node
         */
        score_multiplier = -1;
    }

    priority_delta = score_multiplier * colocation->score;
    dependent->priv->priority = pcmk__add_scores(priority_delta,
                                                 dependent->priv->priority);
    pcmk__rsc_trace(dependent,
                    "Applied %s to %s promotion priority (now %s after %s %d)",
                    colocation->id, dependent->id,
                    pcmk_readable_score(dependent->priv->priority),
                    ((score_multiplier == 1)? "adding" : "subtracting"),
                    colocation->score);

    return priority_delta;
}

/*!
 * \internal
 * \brief Find score of highest-scored node that matches colocation attribute
 *
 * \param[in]     colocation  Colocation constraint being applied
 * \param[in,out] rsc         Resource whose allowed nodes should be searched
 * \param[in]     attr        Colocation attribute name (must not be NULL)
 * \param[in]     value       Colocation attribute value to require
 */
static int
best_node_score_matching_attr(const pcmk__colocation_t *colocation,
                              pcmk_resource_t *rsc, const char *attr,
                              const char *value)
{
    GHashTable *allowed_nodes_orig = NULL;
    GHashTableIter iter;
    pcmk_node_t *node = NULL;
    int best_score = -PCMK_SCORE_INFINITY;
    const char *best_node = NULL;

    if ((colocation != NULL) && (rsc == colocation->dependent)
        && pcmk_is_set(colocation->flags, pcmk__coloc_explicit)
        && pcmk__is_group(rsc->priv->parent)
        && (rsc != rsc->priv->parent->priv->children->data)) {
        /* The resource is a user-configured colocation's explicit dependent,
         * and a group member other than the first, which means the group's
         * location constraint scores were not applied to it (see
         * pcmk__group_apply_location()). Explicitly consider those scores now.
         *
         * @TODO This does leave one suboptimal case: if the group itself or
         * another member other than the first is explicitly colocated with
         * the same primary, the primary will count the group's location scores
         * multiple times. This is much less likely than a single member being
         * explicitly colocated, so it's an acceptable tradeoff for now.
         */
        allowed_nodes_orig = rsc->priv->allowed_nodes;
        rsc->priv->allowed_nodes = pcmk__copy_node_table(allowed_nodes_orig);
        for (GList *loc_iter = rsc->priv->scheduler->priv->location_constraints;
             loc_iter != NULL; loc_iter = loc_iter->next) {

            pcmk__location_t *location = loc_iter->data;

            if (location->rsc == rsc->priv->parent) {
                rsc->priv->cmds->apply_location(rsc, location);
            }
        }
    }

    // Find best allowed node with matching attribute
    g_hash_table_iter_init(&iter, rsc->priv->allowed_nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **) &node)) {

        if ((node->assign->score > best_score)
            && pcmk__node_available(node, pcmk__node_alive|pcmk__node_usable)
            && pcmk__str_eq(value, pcmk__colocation_node_attr(node, attr, rsc),
                            pcmk__str_casei)) {

            best_score = node->assign->score;
            best_node = node->priv->name;
        }
    }

    if (!pcmk__str_eq(attr, CRM_ATTR_UNAME, pcmk__str_none)) {
        if (best_node == NULL) {
            crm_info("No allowed node for %s matches node attribute %s=%s",
                     rsc->id, attr, value);
        } else {
            crm_info("Allowed node %s for %s had best score (%d) "
                     "of those matching node attribute %s=%s",
                     best_node, rsc->id, best_score, attr, value);
        }
    }

    if (allowed_nodes_orig != NULL) {
        g_hash_table_destroy(rsc->priv->allowed_nodes);
        rsc->priv->allowed_nodes = allowed_nodes_orig;
    }
    return best_score;
}

/*!
 * \internal
 * \brief Check whether a resource is allowed only on a single node
 *
 * \param[in] rsc   Resource to check
 *
 * \return \c true if \p rsc is allowed only on one node, otherwise \c false
 */
static bool
allowed_on_one(const pcmk_resource_t *rsc)
{
    GHashTableIter iter;
    pcmk_node_t *allowed_node = NULL;
    int allowed_nodes = 0;

    g_hash_table_iter_init(&iter, rsc->priv->allowed_nodes);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &allowed_node)) {
        if ((allowed_node->assign->score >= 0) && (++allowed_nodes > 1)) {
            pcmk__rsc_trace(rsc, "%s is allowed on multiple nodes", rsc->id);
            return false;
        }
    }
    pcmk__rsc_trace(rsc, "%s is allowed %s", rsc->id,
                    ((allowed_nodes == 1)? "on a single node" : "nowhere"));
    return (allowed_nodes == 1);
}

/*!
 * \internal
 * \brief Add resource's colocation matches to current node assignment scores
 *
 * For each node in a given table, if any of a given resource's allowed nodes
 * have a matching value for the colocation attribute, add the highest of those
 * nodes' scores to the node's score.
 *
 * \param[in,out] nodes          Table of nodes with assignment scores so far
 * \param[in,out] source_rsc     Resource whose node scores to add
 * \param[in]     target_rsc     Resource on whose behalf to update \p nodes
 * \param[in]     colocation     Original colocation constraint (used to get
 *                               configured primary resource's stickiness, and
 *                               to get colocation node attribute; pass NULL to
 *                               ignore stickiness and use default attribute)
 * \param[in]     factor         Factor by which to multiply scores being added
 * \param[in]     only_positive  Whether to add only positive scores
 */
static void
add_node_scores_matching_attr(GHashTable *nodes,
                              pcmk_resource_t *source_rsc,
                              const pcmk_resource_t *target_rsc,
                              const pcmk__colocation_t *colocation,
                              float factor, bool only_positive)
{
    GHashTableIter iter;
    pcmk_node_t *node = NULL;
    const char *attr = colocation->node_attribute;

    // Iterate through each node
    g_hash_table_iter_init(&iter, nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
        float delta_f = 0;
        int delta = 0;
        int score = 0;
        int new_score = 0;
        const char *value = pcmk__colocation_node_attr(node, attr, target_rsc);

        score = best_node_score_matching_attr(colocation, source_rsc, attr, value);

        if ((factor < 0) && (score < 0)) {
            /* If the dependent is anti-colocated, we generally don't want the
             * primary to prefer nodes that the dependent avoids. That could
             * lead to unnecessary shuffling of the primary when the dependent
             * hits its migration threshold somewhere, for example.
             *
             * However, there are cases when it is desirable. If the dependent
             * can't run anywhere but where the primary is, it would be
             * worthwhile to move the primary for the sake of keeping the
             * dependent active.
             *
             * We can't know that exactly at this point since we don't know
             * where the primary will be assigned, but we can limit considering
             * the preference to when the dependent is allowed only on one node.
             * This is less than ideal for multiple reasons:
             *
             * - the dependent could be allowed on more than one node but have
             *   anti-colocation primaries on each;
             * - the dependent could be a clone or bundle with multiple
             *   instances, and the dependent as a whole is allowed on multiple
             *   nodes but some instance still can't run
             * - the dependent has considered node-specific criteria such as
             *   location constraints and stickiness by this point, but might
             *   have other factors that end up disallowing a node
             *
             * but the alternative is making the primary move when it doesn't
             * need to.
             *
             * We also consider the primary's stickiness and influence, so the
             * user has some say in the matter. (This is the configured primary,
             * not a particular instance of the primary, but that doesn't matter
             * unless stickiness uses a rule to vary by node, and that seems
             * acceptable to ignore.)
             */
            if ((colocation->primary->priv->stickiness >= -score)
                || !pcmk__colocation_has_influence(colocation, NULL)
                || !allowed_on_one(colocation->dependent)) {
                crm_trace("%s: Filtering %d + %f * %d "
                          "(double negative disallowed)",
                          pcmk__node_name(node), node->assign->score, factor,
                          score);
                continue;
            }
        }

        if (node->assign->score == INFINITY_HACK) {
            crm_trace("%s: Filtering %d + %f * %d (node was marked unusable)",
                      pcmk__node_name(node), node->assign->score, factor,
                      score);
            continue;
        }

        delta_f = factor * score;

        // Round the number; see http://c-faq.com/fp/round.html
        delta = (int) ((delta_f < 0)? (delta_f - 0.5) : (delta_f + 0.5));

        /* Small factors can obliterate the small scores that are often actually
         * used in configurations. If the score and factor are nonzero, ensure
         * that the result is nonzero as well.
         */
        if ((delta == 0) && (score != 0)) {
            if (factor > 0.0) {
                delta = 1;
            } else if (factor < 0.0) {
                delta = -1;
            }
        }

        new_score = pcmk__add_scores(delta, node->assign->score);

        if (only_positive && (new_score < 0) && (node->assign->score > 0)) {
            crm_trace("%s: Filtering %d + %f * %d = %d "
                      "(negative disallowed, marking node unusable)",
                      pcmk__node_name(node), node->assign->score, factor, score,
                      new_score);
            node->assign->score = INFINITY_HACK;
            continue;
        }

        if (only_positive && (new_score < 0) && (node->assign->score == 0)) {
            crm_trace("%s: Filtering %d + %f * %d = %d (negative disallowed)",
                      pcmk__node_name(node), node->assign->score, factor, score,
                      new_score);
            continue;
        }

        crm_trace("%s: %d + %f * %d = %d", pcmk__node_name(node),
                  node->assign->score, factor, score, new_score);
        node->assign->score = new_score;
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
 * \param[in,out] source_rsc  Resource whose node scores to add
 * \param[in]     target_rsc  Resource on whose behalf to update \p *nodes
 * \param[in]     log_id      Resource ID for logs (if \c NULL, use
 *                            \p source_rsc ID)
 * \param[in,out] nodes       Nodes to update (set initial contents to \c NULL
 *                            to copy allowed nodes from \p source_rsc)
 * \param[in]     colocation  Original colocation constraint (used to get
 *                            configured primary resource's stickiness, and
 *                            to get colocation node attribute; if \c NULL,
 *                            <tt>source_rsc</tt>'s own matching node scores
 *                            will not be added, and \p *nodes must be \c NULL
 *                            as well)
 * \param[in]     factor      Incorporate scores multiplied by this factor
 * \param[in]     flags       Bitmask of enum pcmk__coloc_select values
 *
 * \note \c NULL \p target_rsc, \c NULL \p *nodes, \c NULL \p colocation, and
 *       the \c pcmk__coloc_select_this_with flag are used together (and only by
 *       \c cmp_resources()).
 * \note The caller remains responsible for freeing \p *nodes.
 * \note This is the shared implementation of
 *       \c pcmk__assignment_methods_t:add_colocated_node_scores().
 */
void
pcmk__add_colocated_node_scores(pcmk_resource_t *source_rsc,
                                const pcmk_resource_t *target_rsc,
                                const char *log_id,
                                GHashTable **nodes,
                                const pcmk__colocation_t *colocation,
                                float factor, uint32_t flags)
{
    GHashTable *work = NULL;

    pcmk__assert((source_rsc != NULL) && (nodes != NULL)
                 && ((colocation != NULL)
                     || ((target_rsc == NULL) && (*nodes == NULL))));

    if (log_id == NULL) {
        log_id = source_rsc->id;
    }

    // Avoid infinite recursion
    if (pcmk_is_set(source_rsc->flags, pcmk__rsc_updating_nodes)) {
        pcmk__rsc_info(source_rsc, "%s: Breaking dependency loop at %s",
                       log_id, source_rsc->id);
        return;
    }
    pcmk__set_rsc_flags(source_rsc, pcmk__rsc_updating_nodes);

    if (*nodes == NULL) {
        work = pcmk__copy_node_table(source_rsc->priv->allowed_nodes);
        target_rsc = source_rsc;
    } else {
        const bool pos = pcmk_is_set(flags, pcmk__coloc_select_nonnegative);

        pcmk__rsc_trace(source_rsc, "%s: Merging %s scores from %s (at %.6f)",
                        log_id, (pos? "positive" : "all"), source_rsc->id, factor);
        work = pcmk__copy_node_table(*nodes);
        add_node_scores_matching_attr(work, source_rsc, target_rsc, colocation,
                                      factor, pos);
    }

    if (work == NULL) {
        pcmk__clear_rsc_flags(source_rsc, pcmk__rsc_updating_nodes);
        return;
    }

    /* @TODO Using pcmk__node_banned here instead of pcmk__node_no_negative
     * should allow more dependents to be active. Investigate the results of
     * that on existing regression tests and come up with a new one that
     * is targeted to it.
     */
    if (pcmk__any_node_available(work, pcmk__node_alive
                                       |pcmk__node_usable
                                       |pcmk__node_no_negative)) {
        GList *colocations = NULL;

        if (pcmk_is_set(flags, pcmk__coloc_select_this_with)) {
            colocations = pcmk__this_with_colocations(source_rsc);
            pcmk__rsc_trace(source_rsc,
                            "Checking additional %d optional '%s with' "
                            "constraints",
                            g_list_length(colocations), source_rsc->id);
        } else {
            colocations = pcmk__with_this_colocations(source_rsc);
            pcmk__rsc_trace(source_rsc,
                            "Checking additional %d optional 'with %s' "
                            "constraints",
                            g_list_length(colocations), source_rsc->id);
        }
        flags |= pcmk__coloc_select_active;

        for (GList *iter = colocations; iter != NULL; iter = iter->next) {
            pcmk__colocation_t *constraint = iter->data;

            pcmk_resource_t *other = NULL;
            float other_factor = factor * constraint->score
                                 / (float) PCMK_SCORE_INFINITY;

            if (pcmk_is_set(flags, pcmk__coloc_select_this_with)) {
                other = constraint->primary;
            } else if (!pcmk__colocation_has_influence(constraint, NULL)) {
                continue;
            } else {
                other = constraint->dependent;
            }

            pcmk__rsc_trace(source_rsc,
                            "Optionally merging score of '%s' constraint "
                            "(%s with %s)",
                            constraint->id, constraint->dependent->id,
                            constraint->primary->id);
            other->priv->cmds->add_colocated_node_scores(other, target_rsc,
                                                         log_id, &work,
                                                         constraint,
                                                         other_factor, flags);
            pe__show_node_scores(true, NULL, log_id, work,
                                 source_rsc->priv->scheduler);
        }
        g_list_free(colocations);

    } else if (pcmk_is_set(flags, pcmk__coloc_select_active)) {
        pcmk__rsc_info(source_rsc, "%s: Rolling back optional scores from %s",
                       log_id, source_rsc->id);
        g_hash_table_destroy(work);
        pcmk__clear_rsc_flags(source_rsc, pcmk__rsc_updating_nodes);
        return;
    }


    if (pcmk_is_set(flags, pcmk__coloc_select_nonnegative)) {
        pcmk_node_t *node = NULL;
        GHashTableIter iter;

        g_hash_table_iter_init(&iter, work);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
            if (node->assign->score == INFINITY_HACK) {
                node->assign->score = 1;
            }
        }
    }

    if (*nodes != NULL) {
       g_hash_table_destroy(*nodes);
    }
    *nodes = work;

    pcmk__clear_rsc_flags(source_rsc, pcmk__rsc_updating_nodes);
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
    pcmk__colocation_t *colocation = data;
    pcmk_resource_t *primary = user_data;

    pcmk_resource_t *dependent = colocation->dependent;
    const float factor = colocation->score / (float) PCMK_SCORE_INFINITY;
    uint32_t flags = pcmk__coloc_select_active;

    if (!pcmk__colocation_has_influence(colocation, NULL)) {
        return;
    }
    if (pcmk__is_clone(primary)) {
        flags |= pcmk__coloc_select_nonnegative;
    }
    pcmk__rsc_trace(primary,
                    "%s: Incorporating attenuated %s assignment scores due "
                    "to colocation %s",
                    primary->id, dependent->id, colocation->id);
    dependent->priv->cmds->add_colocated_node_scores(dependent, primary,
                                                     dependent->id,
                                                     &(primary->priv->allowed_nodes),
                                                     colocation, factor, flags);
}

/*!
 * \internal
 * \brief Exclude nodes from a dependent's node table if not in a given list
 *
 * Given a dependent resource in a colocation and a list of nodes where the
 * primary resource will run, set a node's score to \c -INFINITY in the
 * dependent's node table if not found in the primary nodes list.
 *
 * \param[in,out] dependent      Dependent resource
 * \param[in]     primary        Primary resource (for logging only)
 * \param[in]     colocation     Colocation constraint (for logging only)
 * \param[in]     primary_nodes  List of nodes where the primary will have
 *                               unblocked instances in a suitable role
 * \param[in]     merge_scores   If \c true and a node is found in both \p table
 *                               and \p list, add the node's score in \p list to
 *                               the node's score in \p table
 */
void
pcmk__colocation_intersect_nodes(pcmk_resource_t *dependent,
                                 const pcmk_resource_t *primary,
                                 const pcmk__colocation_t *colocation,
                                 const GList *primary_nodes, bool merge_scores)
{
    GHashTableIter iter;
    pcmk_node_t *dependent_node = NULL;

    pcmk__assert((dependent != NULL) && (primary != NULL)
                 && (colocation != NULL));

    g_hash_table_iter_init(&iter, dependent->priv->allowed_nodes);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &dependent_node)) {
        const pcmk_node_t *primary_node = NULL;

        primary_node = pe_find_node_id(primary_nodes,
                                       dependent_node->priv->id);
        if (primary_node == NULL) {
            dependent_node->assign->score = -PCMK_SCORE_INFINITY;
            pcmk__rsc_trace(dependent,
                            "Banning %s from %s (no primary instance) for %s",
                            dependent->id, pcmk__node_name(dependent_node),
                            colocation->id);

        } else if (merge_scores) {
            dependent_node->assign->score =
                pcmk__add_scores(dependent_node->assign->score,
                                 primary_node->assign->score);
            pcmk__rsc_trace(dependent,
                            "Added %s's score %s to %s's score for %s (now %d) "
                            "for colocation %s",
                            primary->id,
                            pcmk_readable_score(primary_node->assign->score),
                            dependent->id, pcmk__node_name(dependent_node),
                            dependent_node->assign->score, colocation->id);
        }
    }
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
pcmk__with_this_colocations(const pcmk_resource_t *rsc)
{
    GList *list = NULL;

    rsc->priv->cmds->with_this_colocations(rsc, rsc, &list);
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
pcmk__this_with_colocations(const pcmk_resource_t *rsc)
{
    GList *list = NULL;

    rsc->priv->cmds->this_with_colocations(rsc, rsc, &list);
    return list;
}

/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <inttypes.h>               // PRIx32
#include <stdbool.h>
#include <glib.h>

#include <crm/crm.h>
#include <pacemaker-internal.h>
#include "libpacemaker_private.h"

enum pe_order_kind {
    pe_order_kind_optional,
    pe_order_kind_mandatory,
    pe_order_kind_serialize,
};

enum ordering_symmetry {
    ordering_asymmetric,        // the only relation in an asymmetric ordering
    ordering_symmetric,         // the normal relation in a symmetric ordering
    ordering_symmetric_inverse, // the inverse relation in a symmetric ordering
};

#define EXPAND_CONSTRAINT_IDREF(__set, __rsc, __name) do {                      \
        __rsc = pcmk__find_constraint_resource(data_set->resources, __name);    \
        if (__rsc == NULL) {                                                    \
            pcmk__config_err("%s: No resource found for %s", __set, __name);    \
            return pcmk_rc_unpack_error;                                        \
        }                                                                       \
    } while (0)

static const char *
invert_action(const char *action)
{
    if (pcmk__str_eq(action, RSC_START, pcmk__str_casei)) {
        return RSC_STOP;

    } else if (pcmk__str_eq(action, RSC_STOP, pcmk__str_casei)) {
        return RSC_START;

    } else if (pcmk__str_eq(action, RSC_PROMOTE, pcmk__str_casei)) {
        return RSC_DEMOTE;

    } else if (pcmk__str_eq(action, RSC_DEMOTE, pcmk__str_casei)) {
        return RSC_PROMOTE;

    } else if (pcmk__str_eq(action, RSC_PROMOTED, pcmk__str_casei)) {
        return RSC_DEMOTED;

    } else if (pcmk__str_eq(action, RSC_DEMOTED, pcmk__str_casei)) {
        return RSC_PROMOTED;

    } else if (pcmk__str_eq(action, RSC_STARTED, pcmk__str_casei)) {
        return RSC_STOPPED;

    } else if (pcmk__str_eq(action, RSC_STOPPED, pcmk__str_casei)) {
        return RSC_STARTED;
    }
    crm_warn("Unknown action '%s' specified in order constraint", action);
    return NULL;
}

static enum pe_order_kind
get_ordering_type(const xmlNode *xml_obj)
{
    enum pe_order_kind kind_e = pe_order_kind_mandatory;
    const char *kind = crm_element_value(xml_obj, XML_ORDER_ATTR_KIND);

    if (kind == NULL) {
        const char *score = crm_element_value(xml_obj, XML_RULE_ATTR_SCORE);

        kind_e = pe_order_kind_mandatory;

        if (score) {
            // @COMPAT deprecated informally since 1.0.7, formally since 2.0.1
            int score_i = char2score(score);

            if (score_i == 0) {
                kind_e = pe_order_kind_optional;
            }
            pe_warn_once(pe_wo_order_score,
                         "Support for 'score' in rsc_order is deprecated "
                         "and will be removed in a future release "
                         "(use 'kind' instead)");
        }

    } else if (pcmk__str_eq(kind, "Mandatory", pcmk__str_casei)) {
        kind_e = pe_order_kind_mandatory;

    } else if (pcmk__str_eq(kind, "Optional", pcmk__str_casei)) {
        kind_e = pe_order_kind_optional;

    } else if (pcmk__str_eq(kind, "Serialize", pcmk__str_casei)) {
        kind_e = pe_order_kind_serialize;

    } else {
        pcmk__config_err("Resetting '" XML_ORDER_ATTR_KIND "' for constraint "
                         "%s to 'Mandatory' because '%s' is not valid",
                         pcmk__s(ID(xml_obj), "missing ID"), kind);
    }
    return kind_e;
}

/*!
 * \internal
 * \brief Get ordering symmetry from XML
 *
 * \param[in] xml_obj               Ordering XML
 * \param[in] parent_kind           Default ordering kind
 * \param[in] parent_symmetrical_s  Parent element's symmetrical setting, if any
 *
 * \retval ordering_symmetric   Ordering is symmetric
 * \retval ordering_asymmetric  Ordering is asymmetric
 */
static enum ordering_symmetry
get_ordering_symmetry(const xmlNode *xml_obj, enum pe_order_kind parent_kind,
                      const char *parent_symmetrical_s)
{
    int rc = pcmk_rc_ok;
    bool symmetric = false;
    enum pe_order_kind kind = parent_kind; // Default to parent's kind

    // Check ordering XML for explicit kind
    if ((crm_element_value(xml_obj, XML_ORDER_ATTR_KIND) != NULL)
        || (crm_element_value(xml_obj, XML_RULE_ATTR_SCORE) != NULL)) {
        kind = get_ordering_type(xml_obj);
    }

    // Check ordering XML (and parent) for explicit symmetrical setting
    rc = pcmk__xe_get_bool_attr(xml_obj, XML_CONS_ATTR_SYMMETRICAL, &symmetric);

    if (rc != pcmk_rc_ok && parent_symmetrical_s != NULL) {
        symmetric = crm_is_true(parent_symmetrical_s);
        rc = pcmk_rc_ok;
    }

    if (rc == pcmk_rc_ok) {
        if (symmetric) {
            if (kind == pe_order_kind_serialize) {
                pcmk__config_warn("Ignoring " XML_CONS_ATTR_SYMMETRICAL
                                  " for '%s' because not valid with "
                                  XML_ORDER_ATTR_KIND " of 'Serialize'",
                                  ID(xml_obj));
            } else {
                return ordering_symmetric;
            }
        }
        return ordering_asymmetric;
    }

    // Use default symmetry
    if (kind == pe_order_kind_serialize) {
        return ordering_asymmetric;
    }
    return ordering_symmetric;
}

/*!
 * \internal
 * \brief Get ordering flags appropriate to ordering kind
 *
 * \param[in] kind      Ordering kind
 * \param[in] first     Action name for 'first' action
 * \param[in] symmetry  This ordering's symmetry role
 *
 * \return Minimal ordering flags appropriate to \p kind
 */
static uint32_t
ordering_flags_for_kind(enum pe_order_kind kind, const char *first,
                        enum ordering_symmetry symmetry)
{
    uint32_t flags = pe_order_none; // so we trace-log all flags set

    pe__set_order_flags(flags, pe_order_optional);

    switch (kind) {
        case pe_order_kind_optional:
            break;

        case pe_order_kind_serialize:
            pe__set_order_flags(flags, pe_order_serialize_only);
            break;

        case pe_order_kind_mandatory:
            switch (symmetry) {
                case ordering_asymmetric:
                    pe__set_order_flags(flags, pe_order_asymmetrical);
                    break;

                case ordering_symmetric:
                    pe__set_order_flags(flags, pe_order_implies_then);
                    if (pcmk__strcase_any_of(first, RSC_START, RSC_PROMOTE,
                                             NULL)) {
                        pe__set_order_flags(flags, pe_order_runnable_left);
                    }
                    break;

                case ordering_symmetric_inverse:
                    pe__set_order_flags(flags, pe_order_implies_first);
                    break;
            }
            break;
    }
    return flags;
}

/*!
 * \internal
 * \brief Find resource corresponding to ID specified in ordering
 *
 * \param[in] xml            Ordering XML
 * \param[in] resource_attr  XML attribute name for resource ID
 * \param[in] instance_attr  XML attribute name for instance number.
 *                           This option is deprecated and will be removed in a
 *                           future release.
 * \param[in] data_set       Cluster working set
 *
 * \return Resource corresponding to \p id, or NULL if none
 */
static pe_resource_t *
get_ordering_resource(const xmlNode *xml, const char *resource_attr,
                      const char *instance_attr,
                      const pe_working_set_t *data_set)
{
    // @COMPAT: instance_attr and instance_id variables deprecated since 2.1.5
    pe_resource_t *rsc = NULL;
    const char *rsc_id = crm_element_value(xml, resource_attr);
    const char *instance_id = crm_element_value(xml, instance_attr);

    if (rsc_id == NULL) {
        pcmk__config_err("Ignoring constraint '%s' without %s",
                         ID(xml), resource_attr);
        return NULL;
    }

    rsc = pcmk__find_constraint_resource(data_set->resources, rsc_id);
    if (rsc == NULL) {
        pcmk__config_err("Ignoring constraint '%s' because resource '%s' "
                         "does not exist", ID(xml), rsc_id);
        return NULL;
    }

    if (instance_id != NULL) {
        pe_warn_once(pe_wo_order_inst,
                     "Support for " XML_ORDER_ATTR_FIRST_INSTANCE " and "
                     XML_ORDER_ATTR_THEN_INSTANCE " is deprecated and will be "
                     "removed in a future release.");

        if (!pe_rsc_is_clone(rsc)) {
            pcmk__config_err("Ignoring constraint '%s' because resource '%s' "
                             "is not a clone but instance '%s' was requested",
                             ID(xml), rsc_id, instance_id);
            return NULL;
        }
        rsc = find_clone_instance(rsc, instance_id);
        if (rsc == NULL) {
            pcmk__config_err("Ignoring constraint '%s' because resource '%s' "
                             "does not have an instance '%s'",
                             "'%s'", ID(xml), rsc_id, instance_id);
            return NULL;
        }
    }
    return rsc;
}

/*!
 * \internal
 * \brief Determine minimum number of 'first' instances required in ordering
 *
 * \param[in] rsc  'First' resource in ordering
 * \param[in] xml  Ordering XML
 *
 * \return Minimum 'first' instances required (or 0 if not applicable)
 */
static int
get_minimum_first_instances(const pe_resource_t *rsc, const xmlNode *xml)
{
    const char *clone_min = NULL;
    bool require_all = false;

    if (!pe_rsc_is_clone(rsc)) {
        return 0;
    }

    clone_min = g_hash_table_lookup(rsc->meta,
                                    XML_RSC_ATTR_INCARNATION_MIN);
    if (clone_min != NULL) {
        int clone_min_int = 0;

        pcmk__scan_min_int(clone_min, &clone_min_int, 0);
        return clone_min_int;
    }

    /* @COMPAT 1.1.13:
     * require-all=false is deprecated equivalent of clone-min=1
     */
    if (pcmk__xe_get_bool_attr(xml, "require-all", &require_all) != ENODATA) {
        pe_warn_once(pe_wo_require_all,
                     "Support for require-all in ordering constraints "
                     "is deprecated and will be removed in a future release"
                     " (use clone-min clone meta-attribute instead)");
        if (!require_all) {
            return 1;
        }
    }

    return 0;
}

/*!
 * \internal
 * \brief Create orderings for a constraint with clone-min > 0
 *
 * \param[in]     id            Ordering ID
 * \param[in,out] rsc_first     'First' resource in ordering (a clone)
 * \param[in]     action_first  'First' action in ordering
 * \param[in]     rsc_then      'Then' resource in ordering
 * \param[in]     action_then   'Then' action in ordering
 * \param[in]     flags         Ordering flags
 * \param[in]     clone_min     Minimum required instances of 'first'
 */
static void
clone_min_ordering(const char *id,
                   pe_resource_t *rsc_first, const char *action_first,
                   pe_resource_t *rsc_then, const char *action_then,
                   uint32_t flags, int clone_min)
{
    // Create a pseudo-action for when the minimum instances are active
    char *task = crm_strdup_printf(CRM_OP_RELAXED_CLONE ":%s", id);
    pe_action_t *clone_min_met = get_pseudo_op(task, rsc_first->cluster);

    free(task);

    /* Require the pseudo-action to have the required number of actions to be
     * considered runnable before allowing the pseudo-action to be runnable.
     */
    clone_min_met->required_runnable_before = clone_min;
    pe__set_action_flags(clone_min_met, pe_action_requires_any);

    // Order the actions for each clone instance before the pseudo-action
    for (GList *rIter = rsc_first->children; rIter != NULL;
         rIter = rIter->next) {

        pe_resource_t *child = rIter->data;

        pcmk__new_ordering(child, pcmk__op_key(child->id, action_first, 0),
                           NULL, NULL, NULL, clone_min_met,
                           pe_order_one_or_more|pe_order_implies_then_printed,
                           rsc_first->cluster);
    }

    // Order "then" action after the pseudo-action (if runnable)
    pcmk__new_ordering(NULL, NULL, clone_min_met, rsc_then,
                       pcmk__op_key(rsc_then->id, action_then, 0),
                       NULL, flags|pe_order_runnable_left, rsc_first->cluster);
}

/*!
 * \internal
 * \brief Update ordering flags for restart-type=restart
 *
 * \param[in]     rsc    'Then' resource in ordering
 * \param[in]     kind   Ordering kind
 * \param[in]     flag   Ordering flag to set (when applicable)
 * \param[in,out] flags  Ordering flag set to update
 *
 * \compat The restart-type resource meta-attribute is deprecated. Eventually,
 *         it will be removed, and pe_restart_ignore will be the only behavior,
 *         at which time this can just be removed entirely.
 */
#define handle_restart_type(rsc, kind, flag, flags) do {        \
        if (((kind) == pe_order_kind_optional)                  \
            && ((rsc)->restart_type == pe_restart_restart)) {   \
            pe__set_order_flags((flags), (flag));               \
        }                                                       \
    } while (0)

/*!
 * \internal
 * \brief Create new ordering for inverse of symmetric constraint
 *
 * \param[in]     id            Ordering ID (for logging only)
 * \param[in]     kind          Ordering kind
 * \param[in]     rsc_first     'First' resource in ordering (a clone)
 * \param[in]     action_first  'First' action in ordering
 * \param[in,out] rsc_then      'Then' resource in ordering
 * \param[in]     action_then   'Then' action in ordering
 */
static void
inverse_ordering(const char *id, enum pe_order_kind kind,
                 pe_resource_t *rsc_first, const char *action_first,
                 pe_resource_t *rsc_then, const char *action_then)
{
    action_then = invert_action(action_then);
    action_first = invert_action(action_first);
    if ((action_then == NULL) || (action_first == NULL)) {
        pcmk__config_warn("Cannot invert constraint '%s' "
                          "(please specify inverse manually)", id);
    } else {
        uint32_t flags = ordering_flags_for_kind(kind, action_first,
                                                 ordering_symmetric_inverse);

        handle_restart_type(rsc_then, kind, pe_order_implies_first, flags);
        pcmk__order_resource_actions(rsc_then, action_then, rsc_first,
                                     action_first, flags);
    }
}

static void
unpack_simple_rsc_order(xmlNode *xml_obj, pe_working_set_t *data_set)
{
    pe_resource_t *rsc_then = NULL;
    pe_resource_t *rsc_first = NULL;
    int min_required_before = 0;
    enum pe_order_kind kind = pe_order_kind_mandatory;
    uint32_t flags = pe_order_none;
    enum ordering_symmetry symmetry;

    const char *action_then = NULL;
    const char *action_first = NULL;
    const char *id = NULL;

    CRM_CHECK(xml_obj != NULL, return);

    id = crm_element_value(xml_obj, XML_ATTR_ID);
    if (id == NULL) {
        pcmk__config_err("Ignoring <%s> constraint without " XML_ATTR_ID,
                         crm_element_name(xml_obj));
        return;
    }

    rsc_first = get_ordering_resource(xml_obj, XML_ORDER_ATTR_FIRST,
                                      XML_ORDER_ATTR_FIRST_INSTANCE,
                                      data_set);
    if (rsc_first == NULL) {
        return;
    }

    rsc_then = get_ordering_resource(xml_obj, XML_ORDER_ATTR_THEN,
                                     XML_ORDER_ATTR_THEN_INSTANCE,
                                     data_set);
    if (rsc_then == NULL) {
        return;
    }

    action_first = crm_element_value(xml_obj, XML_ORDER_ATTR_FIRST_ACTION);
    if (action_first == NULL) {
        action_first = RSC_START;
    }

    action_then = crm_element_value(xml_obj, XML_ORDER_ATTR_THEN_ACTION);
    if (action_then == NULL) {
        action_then = action_first;
    }

    kind = get_ordering_type(xml_obj);

    symmetry = get_ordering_symmetry(xml_obj, kind, NULL);
    flags = ordering_flags_for_kind(kind, action_first, symmetry);

    handle_restart_type(rsc_then, kind, pe_order_implies_then, flags);

    /* If there is a minimum number of instances that must be runnable before
     * the 'then' action is runnable, we use a pseudo-action for convenience:
     * minimum number of clone instances have runnable actions ->
     * pseudo-action is runnable -> dependency is runnable.
     */
    min_required_before = get_minimum_first_instances(rsc_first, xml_obj);
    if (min_required_before > 0) {
        clone_min_ordering(id, rsc_first, action_first, rsc_then, action_then,
                           flags, min_required_before);
    } else {
        pcmk__order_resource_actions(rsc_first, action_first, rsc_then,
                                     action_then, flags);
    }

    if (symmetry == ordering_symmetric) {
        inverse_ordering(id, kind, rsc_first, action_first,
                         rsc_then, action_then);
    }
}

/*!
 * \internal
 * \brief Create a new ordering between two actions
 *
 * \param[in,out] first_rsc          Resource for 'first' action (if NULL and
 *                                   \p first_action is a resource action, that
 *                                   resource will be used)
 * \param[in,out] first_action_task  Action key for 'first' action (if NULL and
 *                                   \p first_action is not NULL, its UUID will
 *                                   be used)
 * \param[in,out] first_action       'first' action (if NULL, \p first_rsc and
 *                                   \p first_action_task must be set)
 *
 * \param[in]     then_rsc           Resource for 'then' action (if NULL and
 *                                   \p then_action is a resource action, that
 *                                   resource will be used)
 * \param[in,out] then_action_task   Action key for 'then' action (if NULL and
 *                                   \p then_action is not NULL, its UUID will
 *                                   be used)
 * \param[in]     then_action        'then' action (if NULL, \p then_rsc and
 *                                   \p then_action_task must be set)
 *
 * \param[in]     flags              Flag set of enum pe_ordering
 * \param[in,out] data_set           Cluster working set to add ordering to
 *
 * \note This function takes ownership of first_action_task and
 *       then_action_task, which do not need to be freed by the caller.
 */
void
pcmk__new_ordering(pe_resource_t *first_rsc, char *first_action_task,
                   pe_action_t *first_action, pe_resource_t *then_rsc,
                   char *then_action_task, pe_action_t *then_action,
                   uint32_t flags, pe_working_set_t *data_set)
{
    pe__ordering_t *order = NULL;

    // One of action or resource must be specified for each side
    CRM_CHECK(((first_action != NULL) || (first_rsc != NULL))
              && ((then_action != NULL) || (then_rsc != NULL)),
              free(first_action_task); free(then_action_task); return);

    if ((first_rsc == NULL) && (first_action != NULL)) {
        first_rsc = first_action->rsc;
    }
    if ((then_rsc == NULL) && (then_action != NULL)) {
        then_rsc = then_action->rsc;
    }

    order = calloc(1, sizeof(pe__ordering_t));
    CRM_ASSERT(order != NULL);

    order->id = data_set->order_id++;
    order->flags = flags;
    order->lh_rsc = first_rsc;
    order->rh_rsc = then_rsc;
    order->lh_action = first_action;
    order->rh_action = then_action;
    order->lh_action_task = first_action_task;
    order->rh_action_task = then_action_task;

    if ((order->lh_action_task == NULL) && (first_action != NULL)) {
        order->lh_action_task = strdup(first_action->uuid);
    }

    if ((order->rh_action_task == NULL) && (then_action != NULL)) {
        order->rh_action_task = strdup(then_action->uuid);
    }

    if ((order->lh_rsc == NULL) && (first_action != NULL)) {
        order->lh_rsc = first_action->rsc;
    }

    if ((order->rh_rsc == NULL) && (then_action != NULL)) {
        order->rh_rsc = then_action->rsc;
    }

    pe_rsc_trace(first_rsc, "Created ordering %d for %s then %s",
                 (data_set->order_id - 1),
                 pcmk__s(order->lh_action_task, "an underspecified action"),
                 pcmk__s(order->rh_action_task, "an underspecified action"));

    data_set->ordering_constraints = g_list_prepend(data_set->ordering_constraints,
                                                    order);
    pcmk__order_migration_equivalents(order);
}

/*!
 * \brief Unpack a set in an ordering constraint
 *
 * \param[in]     set                   Set XML to unpack
 * \param[in]     parent_kind           rsc_order XML "kind" attribute
 * \param[in]     parent_symmetrical_s  rsc_order XML "symmetrical" attribute
 * \param[in,out] data_set              Cluster working set
 *
 * \return Standard Pacemaker return code
 */
static int
unpack_order_set(const xmlNode *set, enum pe_order_kind parent_kind,
                 const char *parent_symmetrical_s, pe_working_set_t *data_set)
{
    GList *set_iter = NULL;
    GList *resources = NULL;

    pe_resource_t *last = NULL;
    pe_resource_t *resource = NULL;

    int local_kind = parent_kind;
    bool sequential = false;
    uint32_t flags = pe_order_optional;
    enum ordering_symmetry symmetry;

    char *key = NULL;
    const char *id = ID(set);
    const char *action = crm_element_value(set, "action");
    const char *sequential_s = crm_element_value(set, "sequential");
    const char *kind_s = crm_element_value(set, XML_ORDER_ATTR_KIND);

    if (action == NULL) {
        action = RSC_START;
    }

    if (kind_s) {
        local_kind = get_ordering_type(set);
    }
    if (sequential_s == NULL) {
        sequential_s = "1";
    }

    sequential = crm_is_true(sequential_s);

    symmetry = get_ordering_symmetry(set, parent_kind, parent_symmetrical_s);
    flags = ordering_flags_for_kind(local_kind, action, symmetry);

    for (const xmlNode *xml_rsc = first_named_child(set, XML_TAG_RESOURCE_REF);
         xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

        EXPAND_CONSTRAINT_IDREF(id, resource, ID(xml_rsc));
        resources = g_list_append(resources, resource);
    }

    if (pcmk__list_of_1(resources)) {
        crm_trace("Single set: %s", id);
        goto done;
    }

    set_iter = resources;
    while (set_iter != NULL) {
        resource = (pe_resource_t *) set_iter->data;
        set_iter = set_iter->next;

        key = pcmk__op_key(resource->id, action, 0);

        if (local_kind == pe_order_kind_serialize) {
            /* Serialize before everything that comes after */

            for (GList *gIter = set_iter; gIter != NULL; gIter = gIter->next) {
                pe_resource_t *then_rsc = (pe_resource_t *) gIter->data;
                char *then_key = pcmk__op_key(then_rsc->id, action, 0);

                pcmk__new_ordering(resource, strdup(key), NULL, then_rsc,
                                   then_key, NULL, flags, data_set);
            }

        } else if (sequential) {
            if (last != NULL) {
                pcmk__order_resource_actions(last, action, resource, action,
                                             flags);
            }
            last = resource;
        }
        free(key);
    }

    if (symmetry == ordering_asymmetric) {
        goto done;
    }

    last = NULL;
    action = invert_action(action);

    flags = ordering_flags_for_kind(local_kind, action,
                                    ordering_symmetric_inverse);

    set_iter = resources;
    while (set_iter != NULL) {
        resource = (pe_resource_t *) set_iter->data;
        set_iter = set_iter->next;

        if (sequential) {
            if (last != NULL) {
                pcmk__order_resource_actions(resource, action, last, action,
                                             flags);
            }
            last = resource;
        }
    }

  done:
    g_list_free(resources);
    return pcmk_rc_ok;
}

/*!
 * \brief Order two resource sets relative to each other
 *
 * \param[in]     id        Ordering ID (for logging)
 * \param[in]     set1      First listed set
 * \param[in]     set2      Second listed set
 * \param[in]     kind      Ordering kind
 * \param[in,out] data_set  Cluster working set
 * \param[in]     symmetry  Which ordering symmetry applies to this relation
 *
 * \return Standard Pacemaker return code
 */
static int
order_rsc_sets(const char *id, const xmlNode *set1, const xmlNode *set2,
               enum pe_order_kind kind, pe_working_set_t *data_set,
               enum ordering_symmetry symmetry)
{

    const xmlNode *xml_rsc = NULL;
    const xmlNode *xml_rsc_2 = NULL;

    pe_resource_t *rsc_1 = NULL;
    pe_resource_t *rsc_2 = NULL;

    const char *action_1 = crm_element_value(set1, "action");
    const char *action_2 = crm_element_value(set2, "action");

    uint32_t flags = pe_order_none;

    bool require_all = true;

    (void) pcmk__xe_get_bool_attr(set1, "require-all", &require_all);

    if (action_1 == NULL) {
        action_1 = RSC_START;
    }

    if (action_2 == NULL) {
        action_2 = RSC_START;
    }

    if (symmetry == ordering_symmetric_inverse) {
        action_1 = invert_action(action_1);
        action_2 = invert_action(action_2);
    }

    if (pcmk__str_eq(RSC_STOP, action_1, pcmk__str_casei)
        || pcmk__str_eq(RSC_DEMOTE, action_1, pcmk__str_casei)) {
        /* Assuming: A -> ( B || C) -> D
         * The one-or-more logic only applies during the start/promote phase.
         * During shutdown neither B nor can shutdown until D is down, so simply
         * turn require_all back on.
         */
        require_all = true;
    }

    flags = ordering_flags_for_kind(kind, action_1, symmetry);

    /* If we have an unordered set1, whether it is sequential or not is
     * irrelevant in regards to set2.
     */
    if (!require_all) {
        char *task = crm_strdup_printf(CRM_OP_RELAXED_SET ":%s", ID(set1));
        pe_action_t *unordered_action = get_pseudo_op(task, data_set);

        free(task);
        pe__set_action_flags(unordered_action, pe_action_requires_any);

        for (xml_rsc = first_named_child(set1, XML_TAG_RESOURCE_REF);
             xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

            EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));

            /* Add an ordering constraint between every element in set1 and the
             * pseudo action. If any action in set1 is runnable the pseudo
             * action will be runnable.
             */
            pcmk__new_ordering(rsc_1, pcmk__op_key(rsc_1->id, action_1, 0),
                               NULL, NULL, NULL, unordered_action,
                               pe_order_one_or_more|pe_order_implies_then_printed,
                               data_set);
        }
        for (xml_rsc_2 = first_named_child(set2, XML_TAG_RESOURCE_REF);
             xml_rsc_2 != NULL; xml_rsc_2 = crm_next_same_xml(xml_rsc_2)) {

            EXPAND_CONSTRAINT_IDREF(id, rsc_2, ID(xml_rsc_2));

            /* Add an ordering constraint between the pseudo-action and every
             * element in set2. If the pseudo-action is runnable, every action
             * in set2 will be runnable.
             */
            pcmk__new_ordering(NULL, NULL, unordered_action,
                               rsc_2, pcmk__op_key(rsc_2->id, action_2, 0),
                               NULL, flags|pe_order_runnable_left, data_set);
        }

        return pcmk_rc_ok;
    }

    if (pcmk__xe_attr_is_true(set1, "sequential")) {
        if (symmetry == ordering_symmetric_inverse) {
            // Get the first one
            xml_rsc = first_named_child(set1, XML_TAG_RESOURCE_REF);
            if (xml_rsc != NULL) {
                EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));
            }

        } else {
            // Get the last one
            const char *rid = NULL;

            for (xml_rsc = first_named_child(set1, XML_TAG_RESOURCE_REF);
                 xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

                rid = ID(xml_rsc);
            }
            EXPAND_CONSTRAINT_IDREF(id, rsc_1, rid);
        }
    }

    if (pcmk__xe_attr_is_true(set2, "sequential")) {
        if (symmetry == ordering_symmetric_inverse) {
            // Get the last one
            const char *rid = NULL;

            for (xml_rsc = first_named_child(set2, XML_TAG_RESOURCE_REF);
                 xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

                rid = ID(xml_rsc);
            }
            EXPAND_CONSTRAINT_IDREF(id, rsc_2, rid);

        } else {
            // Get the first one
            xml_rsc = first_named_child(set2, XML_TAG_RESOURCE_REF);
            if (xml_rsc != NULL) {
                EXPAND_CONSTRAINT_IDREF(id, rsc_2, ID(xml_rsc));
            }
        }
    }

    if ((rsc_1 != NULL) && (rsc_2 != NULL)) {
        pcmk__order_resource_actions(rsc_1, action_1, rsc_2, action_2, flags);

    } else if (rsc_1 != NULL) {
        for (xml_rsc = first_named_child(set2, XML_TAG_RESOURCE_REF);
             xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

            EXPAND_CONSTRAINT_IDREF(id, rsc_2, ID(xml_rsc));
            pcmk__order_resource_actions(rsc_1, action_1, rsc_2, action_2,
                                         flags);
        }

    } else if (rsc_2 != NULL) {
        for (xml_rsc = first_named_child(set1, XML_TAG_RESOURCE_REF);
             xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

            EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));
            pcmk__order_resource_actions(rsc_1, action_1, rsc_2, action_2,
                                         flags);
        }

    } else {
        for (xml_rsc = first_named_child(set1, XML_TAG_RESOURCE_REF);
             xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

            EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));

            for (xmlNode *xml_rsc_2 = first_named_child(set2, XML_TAG_RESOURCE_REF);
                 xml_rsc_2 != NULL; xml_rsc_2 = crm_next_same_xml(xml_rsc_2)) {

                EXPAND_CONSTRAINT_IDREF(id, rsc_2, ID(xml_rsc_2));
                pcmk__order_resource_actions(rsc_1, action_1, rsc_2,
                                             action_2, flags);
            }
        }
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief If an ordering constraint uses resource tags, expand them
 *
 * \param[in,out] xml_obj       Ordering constraint XML
 * \param[out]    expanded_xml  Equivalent XML with tags expanded
 * \param[in]     data_set      Cluster working set
 *
 * \return Standard Pacemaker return code (specifically, pcmk_rc_ok on success,
 *         and pcmk_rc_unpack_error on invalid configuration)
 */
static int
unpack_order_tags(xmlNode *xml_obj, xmlNode **expanded_xml,
                  const pe_working_set_t *data_set)
{
    const char *id_first = NULL;
    const char *id_then = NULL;
    const char *action_first = NULL;
    const char *action_then = NULL;

    pe_resource_t *rsc_first = NULL;
    pe_resource_t *rsc_then = NULL;
    pe_tag_t *tag_first = NULL;
    pe_tag_t *tag_then = NULL;

    xmlNode *rsc_set_first = NULL;
    xmlNode *rsc_set_then = NULL;
    bool any_sets = false;

    // Check whether there are any resource sets with template or tag references
    *expanded_xml = pcmk__expand_tags_in_sets(xml_obj, data_set);
    if (*expanded_xml != NULL) {
        crm_log_xml_trace(*expanded_xml, "Expanded rsc_order");
        return pcmk_rc_ok;
    }

    id_first = crm_element_value(xml_obj, XML_ORDER_ATTR_FIRST);
    id_then = crm_element_value(xml_obj, XML_ORDER_ATTR_THEN);
    if ((id_first == NULL) || (id_then == NULL)) {
        return pcmk_rc_ok;
    }

    if (!pcmk__valid_resource_or_tag(data_set, id_first, &rsc_first,
                                     &tag_first)) {
        pcmk__config_err("Ignoring constraint '%s' because '%s' is not a "
                         "valid resource or tag", ID(xml_obj), id_first);
        return pcmk_rc_unpack_error;
    }

    if (!pcmk__valid_resource_or_tag(data_set, id_then, &rsc_then, &tag_then)) {
        pcmk__config_err("Ignoring constraint '%s' because '%s' is not a "
                         "valid resource or tag", ID(xml_obj), id_then);
        return pcmk_rc_unpack_error;
    }

    if ((rsc_first != NULL) && (rsc_then != NULL)) {
        // Neither side references a template or tag
        return pcmk_rc_ok;
    }

    action_first = crm_element_value(xml_obj, XML_ORDER_ATTR_FIRST_ACTION);
    action_then = crm_element_value(xml_obj, XML_ORDER_ATTR_THEN_ACTION);

    *expanded_xml = copy_xml(xml_obj);

    // Convert template/tag reference in "first" into resource_set under constraint
    if (!pcmk__tag_to_set(*expanded_xml, &rsc_set_first, XML_ORDER_ATTR_FIRST,
                          true, data_set)) {
        free_xml(*expanded_xml);
        *expanded_xml = NULL;
        return pcmk_rc_unpack_error;
    }

    if (rsc_set_first != NULL) {
        if (action_first != NULL) {
            // Move "first-action" into converted resource_set as "action"
            crm_xml_add(rsc_set_first, "action", action_first);
            xml_remove_prop(*expanded_xml, XML_ORDER_ATTR_FIRST_ACTION);
        }
        any_sets = true;
    }

    // Convert template/tag reference in "then" into resource_set under constraint
    if (!pcmk__tag_to_set(*expanded_xml, &rsc_set_then, XML_ORDER_ATTR_THEN,
                          true, data_set)) {
        free_xml(*expanded_xml);
        *expanded_xml = NULL;
        return pcmk_rc_unpack_error;
    }

    if (rsc_set_then != NULL) {
        if (action_then != NULL) {
            // Move "then-action" into converted resource_set as "action"
            crm_xml_add(rsc_set_then, "action", action_then);
            xml_remove_prop(*expanded_xml, XML_ORDER_ATTR_THEN_ACTION);
        }
        any_sets = true;
    }

    if (any_sets) {
        crm_log_xml_trace(*expanded_xml, "Expanded rsc_order");
    } else {
        free_xml(*expanded_xml);
        *expanded_xml = NULL;
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Unpack ordering constraint XML
 *
 * \param[in,out] xml_obj   Ordering constraint XML to unpack
 * \param[in,out] data_set  Cluster working set
 */
void
pcmk__unpack_ordering(xmlNode *xml_obj, pe_working_set_t *data_set)
{
    xmlNode *set = NULL;
    xmlNode *last = NULL;

    xmlNode *orig_xml = NULL;
    xmlNode *expanded_xml = NULL;

    const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
    const char *invert = crm_element_value(xml_obj, XML_CONS_ATTR_SYMMETRICAL);
    enum pe_order_kind kind = get_ordering_type(xml_obj);

    enum ordering_symmetry symmetry = get_ordering_symmetry(xml_obj, kind,
                                                            NULL);

    // Expand any resource tags in the constraint XML
    if (unpack_order_tags(xml_obj, &expanded_xml, data_set) != pcmk_rc_ok) {
        return;
    }
    if (expanded_xml != NULL) {
        orig_xml = xml_obj;
        xml_obj = expanded_xml;
    }

    // If the constraint has resource sets, unpack them
    for (set = first_named_child(xml_obj, XML_CONS_TAG_RSC_SET);
         set != NULL; set = crm_next_same_xml(set)) {

        set = expand_idref(set, data_set->input);
        if ((set == NULL) // Configuration error, message already logged
            || (unpack_order_set(set, kind, invert, data_set) != pcmk_rc_ok)) {

            if (expanded_xml != NULL) {
                free_xml(expanded_xml);
            }
            return;
        }

        if (last != NULL) {

            if (order_rsc_sets(id, last, set, kind, data_set,
                               symmetry) != pcmk_rc_ok) {
                if (expanded_xml != NULL) {
                    free_xml(expanded_xml);
                }
                return;
            }

            if ((symmetry == ordering_symmetric)
                && (order_rsc_sets(id, set, last, kind, data_set,
                                   ordering_symmetric_inverse) != pcmk_rc_ok)) {
                if (expanded_xml != NULL) {
                    free_xml(expanded_xml);
                }
                return;
            }

        }
        last = set;
    }

    if (expanded_xml) {
        free_xml(expanded_xml);
        xml_obj = orig_xml;
    }

    // If the constraint has no resource sets, unpack it as a simple ordering
    if (last == NULL) {
        return unpack_simple_rsc_order(xml_obj, data_set);
    }
}

static bool
ordering_is_invalid(pe_action_t *action, pe_action_wrapper_t *input)
{
    /* Prevent user-defined ordering constraints between resources
     * running in a guest node and the resource that defines that node.
     */
    if (!pcmk_is_set(input->type, pe_order_preserve)
        && (input->action->rsc != NULL)
        && pcmk__rsc_corresponds_to_guest(action->rsc, input->action->node)) {

        crm_warn("Invalid ordering constraint between %s and %s",
                 input->action->rsc->id, action->rsc->id);
        return true;
    }

    /* If there's an order like
     * "rscB_stop node2"-> "load_stopped_node2" -> "rscA_migrate_to node1"
     *
     * then rscA is being migrated from node1 to node2, while rscB is being
     * migrated from node2 to node1. If there would be a graph loop,
     * break the order "load_stopped_node2" -> "rscA_migrate_to node1".
     */
    if ((input->type == pe_order_load) && action->rsc
        && pcmk__str_eq(action->task, RSC_MIGRATE, pcmk__str_casei)
        && pcmk__graph_has_loop(action, action, input)) {
        return true;
    }

    return false;
}

void
pcmk__disable_invalid_orderings(pe_working_set_t *data_set)
{
    for (GList *iter = data_set->actions; iter != NULL; iter = iter->next) {
        pe_action_t *action = (pe_action_t *) iter->data;
        pe_action_wrapper_t *input = NULL;

        for (GList *input_iter = action->actions_before;
             input_iter != NULL; input_iter = input_iter->next) {

            input = (pe_action_wrapper_t *) input_iter->data;
            if (ordering_is_invalid(action, input)) {
                input->type = pe_order_none;
            }
        }
    }
}

/*!
 * \internal
 * \brief Order stops on a node before the node's shutdown
 *
 * \param[in,out] node         Node being shut down
 * \param[in]     shutdown_op  Shutdown action for node
 */
void
pcmk__order_stops_before_shutdown(pe_node_t *node, pe_action_t *shutdown_op)
{
    for (GList *iter = node->details->data_set->actions;
         iter != NULL; iter = iter->next) {

        pe_action_t *action = (pe_action_t *) iter->data;

        // Only stops on the node shutting down are relevant
        if (!pe__same_node(action->node, node)
            || !pcmk__str_eq(action->task, RSC_STOP, pcmk__str_casei)) {
            continue;
        }

        // Resources and nodes in maintenance mode won't be touched

        if (pcmk_is_set(action->rsc->flags, pe_rsc_maintenance)) {
            pe_rsc_trace(action->rsc,
                         "Not ordering %s before shutdown of %s because "
                         "resource in maintenance mode",
                         action->uuid, pe__node_name(node));
            continue;

        } else if (node->details->maintenance) {
            pe_rsc_trace(action->rsc,
                         "Not ordering %s before shutdown of %s because "
                         "node in maintenance mode",
                         action->uuid, pe__node_name(node));
            continue;
        }

        /* Don't touch a resource that is unmanaged or blocked, to avoid
         * blocking the shutdown (though if another action depends on this one,
         * we may still end up blocking)
         */
        if (!pcmk_any_flags_set(action->rsc->flags,
                                pe_rsc_managed|pe_rsc_block)) {
            pe_rsc_trace(action->rsc,
                         "Not ordering %s before shutdown of %s because "
                         "resource is unmanaged or blocked",
                         action->uuid, pe__node_name(node));
            continue;
        }

        pe_rsc_trace(action->rsc, "Ordering %s before shutdown of %s",
                     action->uuid, pe__node_name(node));
        pe__clear_action_flags(action, pe_action_optional);
        pcmk__new_ordering(action->rsc, NULL, action, NULL,
                           strdup(CRM_OP_SHUTDOWN), shutdown_op,
                           pe_order_optional|pe_order_runnable_left,
                           node->details->data_set);
    }
}

/*!
 * \brief Find resource actions matching directly or as child
 *
 * \param[in] rsc           Resource to check
 * \param[in] original_key  Action key to search for (possibly referencing
 *                          parent of \rsc)
 *
 * \return Newly allocated list of matching actions
 * \note It is the caller's responsibility to free the result with g_list_free()
 */
static GList *
find_actions_by_task(const pe_resource_t *rsc, const char *original_key)
{
    // Search under given task key directly
    GList *list = find_actions(rsc->actions, original_key, NULL);

    if (list == NULL) {
        // Search again using this resource's ID
        char *key = NULL;
        char *task = NULL;
        guint interval_ms = 0;

        if (parse_op_key(original_key, NULL, &task, &interval_ms)) {
            key = pcmk__op_key(rsc->id, task, interval_ms);
            list = find_actions(rsc->actions, key, NULL);
            free(key);
            free(task);
        } else {
            crm_err("Invalid operation key (bug?): %s", original_key);
        }
    }
    return list;
}

/*!
 * \internal
 * \brief Order relevant resource actions after a given action
 *
 * \param[in,out] first_action  Action to order after (or NULL if none runnable)
 * \param[in]     rsc           Resource whose actions should be ordered
 * \param[in,out] order         Ordering constraint being applied
 */
static void
order_resource_actions_after(pe_action_t *first_action,
                             const pe_resource_t *rsc, pe__ordering_t *order)
{
    GList *then_actions = NULL;
    uint32_t flags = pe_order_none;

    CRM_CHECK((rsc != NULL) && (order != NULL), return);

    flags = order->flags;
    pe_rsc_trace(rsc, "Applying ordering %d for 'then' resource %s",
                 order->id, rsc->id);

    if (order->rh_action != NULL) {
        then_actions = g_list_prepend(NULL, order->rh_action);

    } else {
        then_actions = find_actions_by_task(rsc, order->rh_action_task);
    }

    if (then_actions == NULL) {
        pe_rsc_trace(rsc, "Ignoring ordering %d: no %s actions found for %s",
                     order->id, order->rh_action_task, rsc->id);
        return;
    }

    if ((first_action != NULL) && (first_action->rsc == rsc)
        && pcmk_is_set(first_action->flags, pe_action_dangle)) {

        pe_rsc_trace(rsc,
                     "Detected dangling migration ordering (%s then %s %s)",
                     first_action->uuid, order->rh_action_task, rsc->id);
        pe__clear_order_flags(flags, pe_order_implies_then);
    }

    if ((first_action == NULL) && !pcmk_is_set(flags, pe_order_implies_then)) {
        pe_rsc_debug(rsc,
                     "Ignoring ordering %d for %s: No first action found",
                     order->id, rsc->id);
        g_list_free(then_actions);
        return;
    }

    for (GList *iter = then_actions; iter != NULL; iter = iter->next) {
        pe_action_t *then_action_iter = (pe_action_t *) iter->data;

        if (first_action != NULL) {
            order_actions(first_action, then_action_iter, flags);
        } else {
            pe__clear_action_flags(then_action_iter, pe_action_runnable);
            crm_warn("%s of %s is unrunnable because there is no %s of %s "
                     "to order it after", then_action_iter->task, rsc->id,
                     order->lh_action_task, order->lh_rsc->id);
        }
    }

    g_list_free(then_actions);
}

static void
rsc_order_first(pe_resource_t *first_rsc, pe__ordering_t *order)
{
    GList *first_actions = NULL;
    pe_action_t *first_action = order->lh_action;
    pe_resource_t *then_rsc = order->rh_rsc;

    CRM_ASSERT(first_rsc != NULL);
    pe_rsc_trace(first_rsc, "Applying ordering constraint %d (first: %s)",
                 order->id, first_rsc->id);

    if (first_action != NULL) {
        first_actions = g_list_prepend(NULL, first_action);

    } else {
        first_actions = find_actions_by_task(first_rsc, order->lh_action_task);
    }

    if ((first_actions == NULL) && (first_rsc == then_rsc)) {
        pe_rsc_trace(first_rsc,
                     "Ignoring constraint %d: first (%s for %s) not found",
                     order->id, order->lh_action_task, first_rsc->id);

    } else if (first_actions == NULL) {
        char *key = NULL;
        char *op_type = NULL;
        guint interval_ms = 0;

        parse_op_key(order->lh_action_task, NULL, &op_type, &interval_ms);
        key = pcmk__op_key(first_rsc->id, op_type, interval_ms);

        if ((first_rsc->fns->state(first_rsc, TRUE) == RSC_ROLE_STOPPED)
            && pcmk__str_eq(op_type, RSC_STOP, pcmk__str_casei)) {
            free(key);
            pe_rsc_trace(first_rsc,
                         "Ignoring constraint %d: first (%s for %s) not found",
                         order->id, order->lh_action_task, first_rsc->id);

        } else if ((first_rsc->fns->state(first_rsc, TRUE) == RSC_ROLE_UNPROMOTED)
                   && pcmk__str_eq(op_type, RSC_DEMOTE, pcmk__str_casei)) {
            free(key);
            pe_rsc_trace(first_rsc,
                         "Ignoring constraint %d: first (%s for %s) not found",
                         order->id, order->lh_action_task, first_rsc->id);

        } else {
            pe_rsc_trace(first_rsc,
                         "Creating first (%s for %s) for constraint %d ",
                         order->lh_action_task, first_rsc->id, order->id);
            first_action = custom_action(first_rsc, key, op_type, NULL, TRUE,
                                         TRUE, first_rsc->cluster);
            first_actions = g_list_prepend(NULL, first_action);
        }

        free(op_type);
    }

    if (then_rsc == NULL) {
        if (order->rh_action == NULL) {
            pe_rsc_trace(first_rsc, "Ignoring constraint %d: then not found",
                         order->id);
            return;
        }
        then_rsc = order->rh_action->rsc;
    }
    for (GList *gIter = first_actions; gIter != NULL; gIter = gIter->next) {
        first_action = (pe_action_t *) gIter->data;

        if (then_rsc == NULL) {
            order_actions(first_action, order->rh_action, order->flags);

        } else {
            order_resource_actions_after(first_action, then_rsc, order);
        }
    }

    g_list_free(first_actions);
}

// GFunc to call pcmk__block_colocation_dependents()
static void
block_colocation_dependents(gpointer data, gpointer user_data)
{
    pcmk__block_colocation_dependents(data);
}

// GFunc to call pcmk__update_action_for_orderings()
static void
update_action_for_orderings(gpointer data, gpointer user_data)
{
    pcmk__update_action_for_orderings((pe_action_t *) data,
                                      (pe_working_set_t *) user_data);
}

void
pcmk__apply_orderings(pe_working_set_t *data_set)
{
    crm_trace("Applying ordering constraints");

    /* Ordering constraints need to be processed in the order they were created.
     * rsc_order_first() and order_resource_actions_after() require the relevant
     * actions to already exist in some cases, but rsc_order_first() will create
     * the 'first' action in certain cases. Thus calling rsc_order_first() can
     * change the behavior of later-created orderings.
     *
     * Also, g_list_append() should be avoided for performance reasons, so we
     * prepend orderings when creating them and reverse the list here.
     *
     * @TODO This is brittle and should be carefully redesigned so that the
     * order of creation doesn't matter, and the reverse becomes unneeded.
     */
    data_set->ordering_constraints = g_list_reverse(data_set->ordering_constraints);

    for (GList *gIter = data_set->ordering_constraints;
         gIter != NULL; gIter = gIter->next) {

        pe__ordering_t *order = gIter->data;
        pe_resource_t *rsc = order->lh_rsc;

        if (rsc != NULL) {
            rsc_order_first(rsc, order);
            continue;
        }

        rsc = order->rh_rsc;
        if (rsc != NULL) {
            order_resource_actions_after(order->lh_action, rsc, order);

        } else {
            crm_trace("Applying ordering constraint %d (non-resource actions)",
                      order->id);
            order_actions(order->lh_action, order->rh_action, order->flags);
        }
    }

    g_list_foreach(data_set->actions, block_colocation_dependents, NULL);

    crm_trace("Ordering probes");
    pcmk__order_probes(data_set);

    crm_trace("Updating %d actions", g_list_length(data_set->actions));
    g_list_foreach(data_set->actions, update_action_for_orderings, data_set);

    pcmk__disable_invalid_orderings(data_set);
}

/*!
 * \internal
 * \brief Order a given action after each action in a given list
 *
 * \param[in,out] after  "After" action
 * \param[in,out] list   List of "before" actions
 */
void
pcmk__order_after_each(pe_action_t *after, GList *list)
{
    const char *after_desc = (after->task == NULL)? after->uuid : after->task;

    for (GList *iter = list; iter != NULL; iter = iter->next) {
        pe_action_t *before = (pe_action_t *) iter->data;
        const char *before_desc = before->task? before->task : before->uuid;

        crm_debug("Ordering %s on %s before %s on %s",
                  before_desc, pe__node_name(before->node),
                  after_desc, pe__node_name(after->node));
        order_actions(before, after, pe_order_optional);
    }
}

/*!
 * \internal
 * \brief Order promotions and demotions for restarts of a clone or bundle
 *
 * \param[in,out] rsc  Clone or bundle to order
 */
void
pcmk__promotable_restart_ordering(pe_resource_t *rsc)
{
    // Order start and promote after all instances are stopped
    pcmk__order_resource_actions(rsc, RSC_STOPPED, rsc, RSC_START,
                                 pe_order_optional);
    pcmk__order_resource_actions(rsc, RSC_STOPPED, rsc, RSC_PROMOTE,
                                 pe_order_optional);

    // Order stop, start, and promote after all instances are demoted
    pcmk__order_resource_actions(rsc, RSC_DEMOTED, rsc, RSC_STOP,
                                 pe_order_optional);
    pcmk__order_resource_actions(rsc, RSC_DEMOTED, rsc, RSC_START,
                                 pe_order_optional);
    pcmk__order_resource_actions(rsc, RSC_DEMOTED, rsc, RSC_PROMOTE,
                                 pe_order_optional);

    // Order promote after all instances are started
    pcmk__order_resource_actions(rsc, RSC_STARTED, rsc, RSC_PROMOTE,
                                 pe_order_optional);

    // Order demote after all instances are demoted
    pcmk__order_resource_actions(rsc, RSC_DEMOTE, rsc, RSC_DEMOTED,
                                 pe_order_optional);
}

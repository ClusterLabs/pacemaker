/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <inttypes.h>               // PRIx32
#include <stdbool.h>                // bool, true, false
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

// @TODO de-functionize this for readability and possibly better log messages
#define EXPAND_CONSTRAINT_IDREF(__set, __rsc, __name) do {                  \
        __rsc = pcmk__find_constraint_resource(scheduler->priv->resources,  \
                                               __name);                     \
        if (__rsc == NULL) {                                                \
            pcmk__config_err("%s: No resource found for %s", __set, __name);\
            return pcmk_rc_unpack_error;                                    \
        }                                                                   \
    } while (0)

static const char *
invert_action(const char *action)
{
    if (pcmk__str_eq(action, PCMK_ACTION_START, pcmk__str_none)) {
        return PCMK_ACTION_STOP;

    } else if (pcmk__str_eq(action, PCMK_ACTION_STOP, pcmk__str_none)) {
        return PCMK_ACTION_START;

    } else if (pcmk__str_eq(action, PCMK_ACTION_PROMOTE, pcmk__str_none)) {
        return PCMK_ACTION_DEMOTE;

    } else if (pcmk__str_eq(action, PCMK_ACTION_DEMOTE, pcmk__str_none)) {
        return PCMK_ACTION_PROMOTE;

    } else if (pcmk__str_eq(action, PCMK_ACTION_PROMOTED, pcmk__str_none)) {
        return PCMK_ACTION_DEMOTED;

    } else if (pcmk__str_eq(action, PCMK_ACTION_DEMOTED, pcmk__str_none)) {
        return PCMK_ACTION_PROMOTED;

    } else if (pcmk__str_eq(action, PCMK_ACTION_RUNNING, pcmk__str_none)) {
        return PCMK_ACTION_STOPPED;

    } else if (pcmk__str_eq(action, PCMK_ACTION_STOPPED, pcmk__str_none)) {
        return PCMK_ACTION_RUNNING;
    }
    pcmk__config_warn("Unknown action '%s' specified in order constraint",
                      action);
    return NULL;
}

static enum pe_order_kind
get_ordering_type(const xmlNode *xml_obj)
{
    enum pe_order_kind kind_e = pe_order_kind_mandatory;
    const char *kind = pcmk__xe_get(xml_obj, PCMK_XA_KIND);

    if (kind == NULL) {
        const char *score = pcmk__xe_get(xml_obj, PCMK_XA_SCORE);

        kind_e = pe_order_kind_mandatory;

        if (score) {
            // @COMPAT deprecated informally since 1.0.7, formally since 2.0.1
            int score_i = 0;

            (void) pcmk_parse_score(score, &score_i, 0);
            if (score_i == 0) {
                kind_e = pe_order_kind_optional;
            }
            pcmk__warn_once(pcmk__wo_order_score,
                            "Support for '" PCMK_XA_SCORE "' in "
                            PCMK_XE_RSC_ORDER " is deprecated and will be "
                            "removed in a future release "
                            "(use '" PCMK_XA_KIND "' instead)");
        }

    } else if (pcmk__str_eq(kind, PCMK_VALUE_MANDATORY, pcmk__str_none)) {
        kind_e = pe_order_kind_mandatory;

    } else if (pcmk__str_eq(kind, PCMK_VALUE_OPTIONAL, pcmk__str_none)) {
        kind_e = pe_order_kind_optional;

    } else if (pcmk__str_eq(kind, PCMK_VALUE_SERIALIZE, pcmk__str_none)) {
        kind_e = pe_order_kind_serialize;

    } else {
        pcmk__config_err("Resetting '" PCMK_XA_KIND "' for constraint %s to "
                         "'" PCMK_VALUE_MANDATORY "' because '%s' is not valid",
                         pcmk__s(pcmk__xe_id(xml_obj), "missing ID"), kind);
    }
    return kind_e;
}

/*!
 * \internal
 * \brief Get ordering symmetry from XML
 *
 * \param[in] xml_obj               Ordering XML
 * \param[in] parent_kind           Default ordering kind
 * \param[in] parent_symmetrical_s  Parent element's \c PCMK_XA_SYMMETRICAL
 *                                  setting, if any
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
    if ((pcmk__xe_get(xml_obj, PCMK_XA_KIND) != NULL)
        || (pcmk__xe_get(xml_obj, PCMK_XA_SCORE) != NULL)) {
        kind = get_ordering_type(xml_obj);
    }

    // Check ordering XML (and parent) for explicit PCMK_XA_SYMMETRICAL setting
    rc = pcmk__xe_get_bool_attr(xml_obj, PCMK_XA_SYMMETRICAL, &symmetric);

    if (rc != pcmk_rc_ok && parent_symmetrical_s != NULL) {
        symmetric = crm_is_true(parent_symmetrical_s);
        rc = pcmk_rc_ok;
    }

    if (rc == pcmk_rc_ok) {
        if (symmetric) {
            if (kind == pe_order_kind_serialize) {
                pcmk__config_warn("Ignoring " PCMK_XA_SYMMETRICAL
                                  " for '%s' because not valid with "
                                  PCMK_XA_KIND " of '" PCMK_VALUE_SERIALIZE "'",
                                  pcmk__xe_id(xml_obj));
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
    uint32_t flags = pcmk__ar_none; // so we trace-log all flags set

    switch (kind) {
        case pe_order_kind_optional:
            pcmk__set_relation_flags(flags, pcmk__ar_ordered);
            break;

        case pe_order_kind_serialize:
            /* This flag is not used anywhere directly but means the relation
             * will not match an equality comparison against pcmk__ar_none or
             * pcmk__ar_ordered.
             */
            pcmk__set_relation_flags(flags, pcmk__ar_serialize);
            break;

        case pe_order_kind_mandatory:
            pcmk__set_relation_flags(flags, pcmk__ar_ordered);
            switch (symmetry) {
                case ordering_asymmetric:
                    pcmk__set_relation_flags(flags, pcmk__ar_asymmetric);
                    break;

                case ordering_symmetric:
                    pcmk__set_relation_flags(flags,
                                             pcmk__ar_first_implies_then);
                    if (pcmk__is_up_action(first)) {
                        pcmk__set_relation_flags(flags,
                                                 pcmk__ar_unrunnable_first_blocks);
                    }
                    break;

                case ordering_symmetric_inverse:
                    pcmk__set_relation_flags(flags,
                                             pcmk__ar_then_implies_first);
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
 * \param[in] scheduler      Scheduler data
 *
 * \return Resource corresponding to \p id, or NULL if none
 */
static pcmk_resource_t *
get_ordering_resource(const xmlNode *xml, const char *resource_attr,
                      const pcmk_scheduler_t *scheduler)
{
    pcmk_resource_t *rsc = NULL;
    const char *rsc_id = pcmk__xe_get(xml, resource_attr);

    if (rsc_id == NULL) {
        pcmk__config_err("Ignoring constraint '%s' without %s",
                         pcmk__xe_id(xml), resource_attr);
        return NULL;
    }

    rsc = pcmk__find_constraint_resource(scheduler->priv->resources, rsc_id);
    if (rsc == NULL) {
        pcmk__config_err("Ignoring constraint '%s' because resource '%s' "
                         "does not exist", pcmk__xe_id(xml), rsc_id);
        return NULL;
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
get_minimum_first_instances(const pcmk_resource_t *rsc, const xmlNode *xml)
{
    const char *clone_min = NULL;
    bool require_all = false;

    if (!pcmk__is_clone(rsc)) {
        return 0;
    }

    clone_min = g_hash_table_lookup(rsc->priv->meta, PCMK_META_CLONE_MIN);
    if (clone_min != NULL) {
        int clone_min_int = 0;

        pcmk__scan_min_int(clone_min, &clone_min_int, 0);
        return clone_min_int;
    }

    /* @COMPAT 1.1.13:
     * PCMK_XA_REQUIRE_ALL=PCMK_VALUE_FALSE is deprecated equivalent of
     * PCMK_META_CLONE_MIN=1
     */
    if (pcmk__xe_get_bool_attr(xml, PCMK_XA_REQUIRE_ALL,
                               &require_all) != ENODATA) {
        pcmk__warn_once(pcmk__wo_require_all,
                        "Support for " PCMK_XA_REQUIRE_ALL " in ordering "
                        "constraints is deprecated and will be removed in a "
                        "future release (use " PCMK_META_CLONE_MIN " clone "
                        "meta-attribute instead)");
        if (!require_all) {
            return 1;
        }
    }

    return 0;
}

/*!
 * \internal
 * \brief Create orderings for a constraint with \c PCMK_META_CLONE_MIN > 0
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
                   pcmk_resource_t *rsc_first, const char *action_first,
                   pcmk_resource_t *rsc_then, const char *action_then,
                   uint32_t flags, int clone_min)
{
    // Create a pseudo-action for when the minimum instances are active
    char *task = crm_strdup_printf(PCMK_ACTION_CLONE_ONE_OR_MORE ":%s", id);
    pcmk_action_t *clone_min_met = get_pseudo_op(task,
                                                 rsc_first->priv->scheduler);

    free(task);

    /* Require the pseudo-action to have the required number of actions to be
     * considered runnable before allowing the pseudo-action to be runnable.
     */
    clone_min_met->required_runnable_before = clone_min;

    // Order the actions for each clone instance before the pseudo-action
    for (GList *iter = rsc_first->priv->children;
         iter != NULL; iter = iter->next) {

        pcmk_resource_t *child = iter->data;

        pcmk__new_ordering(child, pcmk__op_key(child->id, action_first, 0),
                           NULL, NULL, NULL, clone_min_met,
                           pcmk__ar_min_runnable
                           |pcmk__ar_first_implies_then_graphed,
                           rsc_first->priv->scheduler);
    }

    // Order "then" action after the pseudo-action (if runnable)
    pcmk__new_ordering(NULL, NULL, clone_min_met, rsc_then,
                       pcmk__op_key(rsc_then->id, action_then, 0),
                       NULL, flags|pcmk__ar_unrunnable_first_blocks,
                       rsc_first->priv->scheduler);
}

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
                 pcmk_resource_t *rsc_first, const char *action_first,
                 pcmk_resource_t *rsc_then, const char *action_then)
{
    uint32_t flags;
    const char *inverted_first = invert_action(action_first);
    const char *inverted_then = invert_action(action_then);

    if ((inverted_then == NULL) || (inverted_first == NULL)) {
        pcmk__config_warn("Cannot invert constraint '%s' "
                          "(please specify inverse manually)", id);
        return;
    }

    // Order inverted actions
    flags = ordering_flags_for_kind(kind, inverted_first,
                                    ordering_symmetric_inverse);
    pcmk__order_resource_actions(rsc_then, inverted_then,
                                 rsc_first, inverted_first, flags);
}

static void
unpack_simple_rsc_order(xmlNode *xml_obj, pcmk_scheduler_t *scheduler)
{
    pcmk_resource_t *rsc_then = NULL;
    pcmk_resource_t *rsc_first = NULL;
    int min_required_before = 0;
    enum pe_order_kind kind = pe_order_kind_mandatory;
    uint32_t flags = pcmk__ar_none;
    enum ordering_symmetry symmetry;

    const char *action_then = NULL;
    const char *action_first = NULL;
    const char *id = NULL;

    CRM_CHECK(xml_obj != NULL, return);

    id = pcmk__xe_get(xml_obj, PCMK_XA_ID);
    if (id == NULL) {
        pcmk__config_err("Ignoring <%s> constraint without " PCMK_XA_ID,
                         xml_obj->name);
        return;
    }

    rsc_first = get_ordering_resource(xml_obj, PCMK_XA_FIRST, scheduler);
    if (rsc_first == NULL) {
        return;
    }

    rsc_then = get_ordering_resource(xml_obj, PCMK_XA_THEN, scheduler);
    if (rsc_then == NULL) {
        return;
    }

    action_first = pcmk__xe_get(xml_obj, PCMK_XA_FIRST_ACTION);
    if (action_first == NULL) {
        action_first = PCMK_ACTION_START;
    }

    action_then = pcmk__xe_get(xml_obj, PCMK_XA_THEN_ACTION);
    if (action_then == NULL) {
        action_then = action_first;
    }

    kind = get_ordering_type(xml_obj);

    symmetry = get_ordering_symmetry(xml_obj, kind, NULL);
    flags = ordering_flags_for_kind(kind, action_first, symmetry);

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
 * \param[in]     flags              Group of enum pcmk__action_relation_flags
 * \param[in,out] sched              Scheduler data to add ordering to
 *
 * \note This function takes ownership of first_action_task and
 *       then_action_task, which do not need to be freed by the caller.
 */
void
pcmk__new_ordering(pcmk_resource_t *first_rsc, char *first_action_task,
                   pcmk_action_t *first_action, pcmk_resource_t *then_rsc,
                   char *then_action_task, pcmk_action_t *then_action,
                   uint32_t flags, pcmk_scheduler_t *sched)
{
    pcmk__action_relation_t *order = NULL;

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

    order = pcmk__assert_alloc(1, sizeof(pcmk__action_relation_t));

    order->id = sched->priv->next_ordering_id++;
    order->flags = flags;
    order->rsc1 = first_rsc;
    order->rsc2 = then_rsc;
    order->action1 = first_action;
    order->action2 = then_action;
    order->task1 = first_action_task;
    order->task2 = then_action_task;

    if ((order->task1 == NULL) && (first_action != NULL)) {
        order->task1 = strdup(first_action->uuid);
    }

    if ((order->task2 == NULL) && (then_action != NULL)) {
        order->task2 = strdup(then_action->uuid);
    }

    if ((order->rsc1 == NULL) && (first_action != NULL)) {
        order->rsc1 = first_action->rsc;
    }

    if ((order->rsc2 == NULL) && (then_action != NULL)) {
        order->rsc2 = then_action->rsc;
    }

    pcmk__rsc_trace(first_rsc, "Created ordering %d for %s then %s",
                    (sched->priv->next_ordering_id - 1),
                    pcmk__s(order->task1, "an underspecified action"),
                    pcmk__s(order->task2, "an underspecified action"));

    sched->priv->ordering_constraints =
        g_list_prepend(sched->priv->ordering_constraints, order);
    pcmk__order_migration_equivalents(order);
}

/*!
 * \brief Unpack a set in an ordering constraint
 *
 * \param[in]     set                   Set XML to unpack
 * \param[in]     parent_kind           \c PCMK_XE_RSC_ORDER XML \c PCMK_XA_KIND
 *                                      attribute
 * \param[in]     parent_symmetrical_s  \c PCMK_XE_RSC_ORDER XML
 *                                      \c PCMK_XA_SYMMETRICAL attribute
 * \param[in,out] scheduler             Scheduler data
 *
 * \return Standard Pacemaker return code
 */
static int
unpack_order_set(const xmlNode *set, enum pe_order_kind parent_kind,
                 const char *parent_symmetrical_s, pcmk_scheduler_t *scheduler)
{
    GList *set_iter = NULL;
    GList *resources = NULL;

    pcmk_resource_t *last = NULL;
    pcmk_resource_t *resource = NULL;

    int local_kind = parent_kind;
    bool sequential = false;
    uint32_t flags = pcmk__ar_ordered;
    enum ordering_symmetry symmetry;

    char *key = NULL;
    const char *id = pcmk__xe_id(set);
    const char *action = pcmk__xe_get(set, PCMK_XA_ACTION);
    const char *sequential_s = pcmk__xe_get(set, PCMK_XA_SEQUENTIAL);
    const char *kind_s = pcmk__xe_get(set, PCMK_XA_KIND);

    if (action == NULL) {
        action = PCMK_ACTION_START;
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

    for (const xmlNode *xml_rsc = pcmk__xe_first_child(set,
                                                       PCMK_XE_RESOURCE_REF,
                                                       NULL, NULL);
         xml_rsc != NULL;
         xml_rsc = pcmk__xe_next(xml_rsc, PCMK_XE_RESOURCE_REF)) {

        EXPAND_CONSTRAINT_IDREF(id, resource, pcmk__xe_id(xml_rsc));
        resources = g_list_append(resources, resource);
    }

    if (pcmk__list_of_1(resources)) {
        crm_trace("Single set: %s", id);
        goto done;
    }

    set_iter = resources;
    while (set_iter != NULL) {
        resource = (pcmk_resource_t *) set_iter->data;
        set_iter = set_iter->next;

        key = pcmk__op_key(resource->id, action, 0);

        if (local_kind == pe_order_kind_serialize) {
            /* Serialize before everything that comes after */

            for (GList *iter = set_iter; iter != NULL; iter = iter->next) {
                pcmk_resource_t *then_rsc = iter->data;
                char *then_key = pcmk__op_key(then_rsc->id, action, 0);

                pcmk__new_ordering(resource, strdup(key), NULL, then_rsc,
                                   then_key, NULL, flags, scheduler);
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
        resource = (pcmk_resource_t *) set_iter->data;
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
 * \param[in]     id         Ordering ID (for logging)
 * \param[in]     set1       First listed set
 * \param[in]     set2       Second listed set
 * \param[in]     kind       Ordering kind
 * \param[in,out] scheduler  Scheduler data
 * \param[in]     symmetry   Which ordering symmetry applies to this relation
 *
 * \return Standard Pacemaker return code
 */
static int
order_rsc_sets(const char *id, const xmlNode *set1, const xmlNode *set2,
               enum pe_order_kind kind, pcmk_scheduler_t *scheduler,
               enum ordering_symmetry symmetry)
{

    const xmlNode *xml_rsc = NULL;
    const xmlNode *xml_rsc_2 = NULL;

    pcmk_resource_t *rsc_1 = NULL;
    pcmk_resource_t *rsc_2 = NULL;

    const char *action_1 = pcmk__xe_get(set1, PCMK_XA_ACTION);
    const char *action_2 = pcmk__xe_get(set2, PCMK_XA_ACTION);

    uint32_t flags = pcmk__ar_none;

    bool require_all = true;

    (void) pcmk__xe_get_bool_attr(set1, PCMK_XA_REQUIRE_ALL, &require_all);

    if (action_1 == NULL) {
        action_1 = PCMK_ACTION_START;
    }

    if (action_2 == NULL) {
        action_2 = PCMK_ACTION_START;
    }

    if (symmetry == ordering_symmetric_inverse) {
        action_1 = invert_action(action_1);
        action_2 = invert_action(action_2);
    }

    if (pcmk__str_eq(PCMK_ACTION_STOP, action_1, pcmk__str_none)
        || pcmk__str_eq(PCMK_ACTION_DEMOTE, action_1, pcmk__str_none)) {
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
        char *task = crm_strdup_printf(PCMK_ACTION_ONE_OR_MORE ":%s",
                                       pcmk__xe_id(set1));
        pcmk_action_t *unordered_action = get_pseudo_op(task, scheduler);

        free(task);
        unordered_action->required_runnable_before = 1;

        for (xml_rsc = pcmk__xe_first_child(set1, PCMK_XE_RESOURCE_REF, NULL,
                                            NULL);
             xml_rsc != NULL;
             xml_rsc = pcmk__xe_next(xml_rsc, PCMK_XE_RESOURCE_REF)) {

            EXPAND_CONSTRAINT_IDREF(id, rsc_1, pcmk__xe_id(xml_rsc));

            /* Add an ordering constraint between every element in set1 and the
             * pseudo action. If any action in set1 is runnable the pseudo
             * action will be runnable.
             */
            pcmk__new_ordering(rsc_1, pcmk__op_key(rsc_1->id, action_1, 0),
                               NULL, NULL, NULL, unordered_action,
                               pcmk__ar_min_runnable
                               |pcmk__ar_first_implies_then_graphed,
                               scheduler);
        }
        for (xml_rsc_2 = pcmk__xe_first_child(set2, PCMK_XE_RESOURCE_REF, NULL,
                                              NULL);
             xml_rsc_2 != NULL;
             xml_rsc_2 = pcmk__xe_next(xml_rsc_2, PCMK_XE_RESOURCE_REF)) {

            EXPAND_CONSTRAINT_IDREF(id, rsc_2, pcmk__xe_id(xml_rsc_2));

            /* Add an ordering constraint between the pseudo-action and every
             * element in set2. If the pseudo-action is runnable, every action
             * in set2 will be runnable.
             */
            pcmk__new_ordering(NULL, NULL, unordered_action,
                               rsc_2, pcmk__op_key(rsc_2->id, action_2, 0),
                               NULL, flags|pcmk__ar_unrunnable_first_blocks,
                               scheduler);
        }

        return pcmk_rc_ok;
    }

    if (pcmk__xe_attr_is_true(set1, PCMK_XA_SEQUENTIAL)) {
        if (symmetry == ordering_symmetric_inverse) {
            // Get the first one
            xml_rsc = pcmk__xe_first_child(set1, PCMK_XE_RESOURCE_REF, NULL,
                                           NULL);
            if (xml_rsc != NULL) {
                EXPAND_CONSTRAINT_IDREF(id, rsc_1, pcmk__xe_id(xml_rsc));
            }

        } else {
            // Get the last one
            const char *rid = NULL;

            for (xml_rsc = pcmk__xe_first_child(set1, PCMK_XE_RESOURCE_REF,
                                                NULL, NULL);
                 xml_rsc != NULL;
                 xml_rsc = pcmk__xe_next(xml_rsc, PCMK_XE_RESOURCE_REF)) {

                rid = pcmk__xe_id(xml_rsc);
            }
            EXPAND_CONSTRAINT_IDREF(id, rsc_1, rid);
        }
    }

    if (pcmk__xe_attr_is_true(set2, PCMK_XA_SEQUENTIAL)) {
        if (symmetry == ordering_symmetric_inverse) {
            // Get the last one
            const char *rid = NULL;

            for (xml_rsc = pcmk__xe_first_child(set2, PCMK_XE_RESOURCE_REF,
                                                NULL, NULL);
                 xml_rsc != NULL;
                 xml_rsc = pcmk__xe_next(xml_rsc, PCMK_XE_RESOURCE_REF)) {

                rid = pcmk__xe_id(xml_rsc);
            }
            EXPAND_CONSTRAINT_IDREF(id, rsc_2, rid);

        } else {
            // Get the first one
            xml_rsc = pcmk__xe_first_child(set2, PCMK_XE_RESOURCE_REF, NULL,
                                           NULL);
            if (xml_rsc != NULL) {
                EXPAND_CONSTRAINT_IDREF(id, rsc_2, pcmk__xe_id(xml_rsc));
            }
        }
    }

    if ((rsc_1 != NULL) && (rsc_2 != NULL)) {
        pcmk__order_resource_actions(rsc_1, action_1, rsc_2, action_2, flags);

    } else if (rsc_1 != NULL) {
        for (xml_rsc = pcmk__xe_first_child(set2, PCMK_XE_RESOURCE_REF, NULL,
                                            NULL);
             xml_rsc != NULL;
             xml_rsc = pcmk__xe_next(xml_rsc, PCMK_XE_RESOURCE_REF)) {

            EXPAND_CONSTRAINT_IDREF(id, rsc_2, pcmk__xe_id(xml_rsc));
            pcmk__order_resource_actions(rsc_1, action_1, rsc_2, action_2,
                                         flags);
        }

    } else if (rsc_2 != NULL) {
        for (xml_rsc = pcmk__xe_first_child(set1, PCMK_XE_RESOURCE_REF, NULL,
                                            NULL);
             xml_rsc != NULL;
             xml_rsc = pcmk__xe_next(xml_rsc, PCMK_XE_RESOURCE_REF)) {

            EXPAND_CONSTRAINT_IDREF(id, rsc_1, pcmk__xe_id(xml_rsc));
            pcmk__order_resource_actions(rsc_1, action_1, rsc_2, action_2,
                                         flags);
        }

    } else {
        for (xml_rsc = pcmk__xe_first_child(set1, PCMK_XE_RESOURCE_REF, NULL,
                                            NULL);
             xml_rsc != NULL;
             xml_rsc = pcmk__xe_next(xml_rsc, PCMK_XE_RESOURCE_REF)) {

            EXPAND_CONSTRAINT_IDREF(id, rsc_1, pcmk__xe_id(xml_rsc));

            for (xmlNode *xml_rsc_2 = pcmk__xe_first_child(set2,
                                                           PCMK_XE_RESOURCE_REF,
                                                           NULL, NULL);
                 xml_rsc_2 != NULL;
                 xml_rsc_2 = pcmk__xe_next(xml_rsc_2, PCMK_XE_RESOURCE_REF)) {

                EXPAND_CONSTRAINT_IDREF(id, rsc_2, pcmk__xe_id(xml_rsc_2));
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
 * \param[in]     scheduler     Scheduler data
 *
 * \return Standard Pacemaker return code (specifically, pcmk_rc_ok on success,
 *         and pcmk_rc_unpack_error on invalid configuration)
 */
static int
unpack_order_tags(xmlNode *xml_obj, xmlNode **expanded_xml,
                  const pcmk_scheduler_t *scheduler)
{
    const char *id_first = NULL;
    const char *id_then = NULL;
    const char *action_first = NULL;
    const char *action_then = NULL;

    pcmk_resource_t *rsc_first = NULL;
    pcmk_resource_t *rsc_then = NULL;
    pcmk__idref_t *tag_first = NULL;
    pcmk__idref_t *tag_then = NULL;

    xmlNode *rsc_set_first = NULL;
    xmlNode *rsc_set_then = NULL;
    bool any_sets = false;

    // Check whether there are any resource sets with template or tag references
    *expanded_xml = pcmk__expand_tags_in_sets(xml_obj, scheduler);
    if (*expanded_xml != NULL) {
        crm_log_xml_trace(*expanded_xml, "Expanded " PCMK_XE_RSC_ORDER);
        return pcmk_rc_ok;
    }

    id_first = pcmk__xe_get(xml_obj, PCMK_XA_FIRST);
    id_then = pcmk__xe_get(xml_obj, PCMK_XA_THEN);
    if ((id_first == NULL) || (id_then == NULL)) {
        return pcmk_rc_ok;
    }

    if (!pcmk__valid_resource_or_tag(scheduler, id_first, &rsc_first,
                                     &tag_first)) {
        pcmk__config_err("Ignoring constraint '%s' because '%s' is not a "
                         "valid resource or tag",
                         pcmk__xe_id(xml_obj), id_first);
        return pcmk_rc_unpack_error;
    }

    if (!pcmk__valid_resource_or_tag(scheduler, id_then, &rsc_then,
                                     &tag_then)) {
        pcmk__config_err("Ignoring constraint '%s' because '%s' is not a "
                         "valid resource or tag",
                         pcmk__xe_id(xml_obj), id_then);
        return pcmk_rc_unpack_error;
    }

    if ((rsc_first != NULL) && (rsc_then != NULL)) {
        // Neither side references a template or tag
        return pcmk_rc_ok;
    }

    action_first = pcmk__xe_get(xml_obj, PCMK_XA_FIRST_ACTION);
    action_then = pcmk__xe_get(xml_obj, PCMK_XA_THEN_ACTION);

    *expanded_xml = pcmk__xml_copy(NULL, xml_obj);

    /* Convert template/tag reference in PCMK_XA_FIRST into constraint
     * PCMK_XE_RESOURCE_SET
     */
    if (!pcmk__tag_to_set(*expanded_xml, &rsc_set_first, PCMK_XA_FIRST, true,
                          scheduler)) {
        pcmk__xml_free(*expanded_xml);
        *expanded_xml = NULL;
        return pcmk_rc_unpack_error;
    }

    if (rsc_set_first != NULL) {
        if (action_first != NULL) {
            /* Move PCMK_XA_FIRST_ACTION into converted PCMK_XE_RESOURCE_SET as
             * PCMK_XA_ACTION
             */
            crm_xml_add(rsc_set_first, PCMK_XA_ACTION, action_first);
            pcmk__xe_remove_attr(*expanded_xml, PCMK_XA_FIRST_ACTION);
        }
        any_sets = true;
    }

    /* Convert template/tag reference in PCMK_XA_THEN into constraint
     * PCMK_XE_RESOURCE_SET
     */
    if (!pcmk__tag_to_set(*expanded_xml, &rsc_set_then, PCMK_XA_THEN, true,
                          scheduler)) {
        pcmk__xml_free(*expanded_xml);
        *expanded_xml = NULL;
        return pcmk_rc_unpack_error;
    }

    if (rsc_set_then != NULL) {
        if (action_then != NULL) {
            /* Move PCMK_XA_THEN_ACTION into converted PCMK_XE_RESOURCE_SET as
             * PCMK_XA_ACTION
             */
            crm_xml_add(rsc_set_then, PCMK_XA_ACTION, action_then);
            pcmk__xe_remove_attr(*expanded_xml, PCMK_XA_THEN_ACTION);
        }
        any_sets = true;
    }

    if (any_sets) {
        crm_log_xml_trace(*expanded_xml, "Expanded " PCMK_XE_RSC_ORDER);
    } else {
        pcmk__xml_free(*expanded_xml);
        *expanded_xml = NULL;
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Unpack ordering constraint XML
 *
 * \param[in,out] xml_obj    Ordering constraint XML to unpack
 * \param[in,out] scheduler  Scheduler data
 */
void
pcmk__unpack_ordering(xmlNode *xml_obj, pcmk_scheduler_t *scheduler)
{
    xmlNode *set = NULL;
    xmlNode *last = NULL;

    xmlNode *orig_xml = NULL;
    xmlNode *expanded_xml = NULL;

    const char *id = pcmk__xe_get(xml_obj, PCMK_XA_ID);
    const char *invert = pcmk__xe_get(xml_obj, PCMK_XA_SYMMETRICAL);
    enum pe_order_kind kind = get_ordering_type(xml_obj);

    enum ordering_symmetry symmetry = get_ordering_symmetry(xml_obj, kind,
                                                            NULL);

    // Expand any resource tags in the constraint XML
    if (unpack_order_tags(xml_obj, &expanded_xml, scheduler) != pcmk_rc_ok) {
        return;
    }
    if (expanded_xml != NULL) {
        orig_xml = xml_obj;
        xml_obj = expanded_xml;
    }

    // If the constraint has resource sets, unpack them
    for (set = pcmk__xe_first_child(xml_obj, PCMK_XE_RESOURCE_SET, NULL, NULL);
         set != NULL; set = pcmk__xe_next(set, PCMK_XE_RESOURCE_SET)) {

        set = pcmk__xe_resolve_idref(set, scheduler->input);
        if ((set == NULL) // Configuration error, message already logged
            || (unpack_order_set(set, kind, invert, scheduler) != pcmk_rc_ok)) {

            if (expanded_xml != NULL) {
                pcmk__xml_free(expanded_xml);
            }
            return;
        }

        if (last != NULL) {

            if (order_rsc_sets(id, last, set, kind, scheduler,
                               symmetry) != pcmk_rc_ok) {
                if (expanded_xml != NULL) {
                    pcmk__xml_free(expanded_xml);
                }
                return;
            }

            if ((symmetry == ordering_symmetric)
                && (order_rsc_sets(id, set, last, kind, scheduler,
                                   ordering_symmetric_inverse) != pcmk_rc_ok)) {
                if (expanded_xml != NULL) {
                    pcmk__xml_free(expanded_xml);
                }
                return;
            }

        }
        last = set;
    }

    if (expanded_xml) {
        pcmk__xml_free(expanded_xml);
        xml_obj = orig_xml;
    }

    // If the constraint has no resource sets, unpack it as a simple ordering
    if (last == NULL) {
        return unpack_simple_rsc_order(xml_obj, scheduler);
    }
}

static bool
ordering_is_invalid(pcmk_action_t *action, pcmk__related_action_t *input)
{
    /* Prevent user-defined ordering constraints between resources
     * running in a guest node and the resource that defines that node.
     */
    if (!pcmk_is_set(input->flags, pcmk__ar_guest_allowed)
        && (input->action->rsc != NULL)
        && pcmk__rsc_corresponds_to_guest(action->rsc, input->action->node)) {

        pcmk__config_warn("Invalid ordering constraint between %s and %s",
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
    if ((input->flags == pcmk__ar_if_on_same_node_or_target)
        && (action->rsc != NULL)
        && pcmk__str_eq(action->task, PCMK_ACTION_MIGRATE_TO, pcmk__str_none)
        && pcmk__graph_has_loop(action, action, input)) {
        return true;
    }

    return false;
}

void
pcmk__disable_invalid_orderings(pcmk_scheduler_t *scheduler)
{
    for (GList *iter = scheduler->priv->actions;
         iter != NULL; iter = iter->next) {

        pcmk_action_t *action = (pcmk_action_t *) iter->data;
        pcmk__related_action_t *input = NULL;

        for (GList *input_iter = action->actions_before;
             input_iter != NULL; input_iter = input_iter->next) {

            input = input_iter->data;
            if (ordering_is_invalid(action, input)) {
                input->flags = pcmk__ar_none;
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
pcmk__order_stops_before_shutdown(pcmk_node_t *node, pcmk_action_t *shutdown_op)
{
    for (GList *iter = node->priv->scheduler->priv->actions;
         iter != NULL; iter = iter->next) {

        pcmk_action_t *action = (pcmk_action_t *) iter->data;

        // Only stops on the node shutting down are relevant
        if (!pcmk__same_node(action->node, node)
            || !pcmk__str_eq(action->task, PCMK_ACTION_STOP, pcmk__str_none)) {
            continue;
        }

        // Resources and nodes in maintenance mode won't be touched

        if (pcmk_is_set(action->rsc->flags, pcmk__rsc_maintenance)) {
            pcmk__rsc_trace(action->rsc,
                            "Not ordering %s before shutdown of %s because "
                            "resource in maintenance mode",
                            action->uuid, pcmk__node_name(node));
            continue;

        } else if (node->details->maintenance) {
            pcmk__rsc_trace(action->rsc,
                            "Not ordering %s before shutdown of %s because "
                            "node in maintenance mode",
                            action->uuid, pcmk__node_name(node));
            continue;
        }

        /* Don't touch a resource that is unmanaged or blocked, to avoid
         * blocking the shutdown (though if another action depends on this one,
         * we may still end up blocking)
         *
         * @TODO This "if" looks wrong, create a regression test for these cases
         */
        if (!pcmk_any_flags_set(action->rsc->flags,
                                pcmk__rsc_managed|pcmk__rsc_blocked)) {
            pcmk__rsc_trace(action->rsc,
                            "Not ordering %s before shutdown of %s because "
                            "resource is unmanaged or blocked",
                            action->uuid, pcmk__node_name(node));
            continue;
        }

        pcmk__rsc_trace(action->rsc, "Ordering %s before shutdown of %s",
                        action->uuid, pcmk__node_name(node));
        pcmk__clear_action_flags(action, pcmk__action_optional);
        pcmk__new_ordering(action->rsc, NULL, action, NULL,
                           strdup(PCMK_ACTION_DO_SHUTDOWN), shutdown_op,
                           pcmk__ar_ordered|pcmk__ar_unrunnable_first_blocks,
                           node->priv->scheduler);
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
find_actions_by_task(const pcmk_resource_t *rsc, const char *original_key)
{
    // Search under given task key directly
    GList *list = find_actions(rsc->priv->actions, original_key, NULL);

    if (list == NULL) {
        // Search again using this resource's ID
        char *key = NULL;
        char *task = NULL;
        guint interval_ms = 0;

        CRM_CHECK(parse_op_key(original_key, NULL, &task, &interval_ms),
                  return NULL);
        key = pcmk__op_key(rsc->id, task, interval_ms);
        list = find_actions(rsc->priv->actions, key, NULL);
        free(key);
        free(task);
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
order_resource_actions_after(pcmk_action_t *first_action,
                             const pcmk_resource_t *rsc,
                             pcmk__action_relation_t *order)
{
    GList *then_actions = NULL;
    uint32_t flags = pcmk__ar_none;

    CRM_CHECK((rsc != NULL) && (order != NULL), return);

    flags = order->flags;
    pcmk__rsc_trace(rsc, "Applying ordering %d for 'then' resource %s",
                    order->id, rsc->id);

    if (order->action2 != NULL) {
        then_actions = g_list_prepend(NULL, order->action2);

    } else {
        then_actions = find_actions_by_task(rsc, order->task2);
    }

    if (then_actions == NULL) {
        pcmk__rsc_trace(rsc, "Ignoring ordering %d: no %s actions found for %s",
                        order->id, order->task2, rsc->id);
        return;
    }

    if ((first_action != NULL) && (first_action->rsc == rsc)
        && pcmk_is_set(first_action->flags, pcmk__action_migration_abort)) {

        pcmk__rsc_trace(rsc,
                        "Detected dangling migration ordering (%s then %s %s)",
                        first_action->uuid, order->task2, rsc->id);
        pcmk__clear_relation_flags(flags, pcmk__ar_first_implies_then);
    }

    if ((first_action == NULL)
        && !pcmk_is_set(flags, pcmk__ar_first_implies_then)) {

        pcmk__rsc_debug(rsc,
                        "Ignoring ordering %d for %s: No first action found",
                        order->id, rsc->id);
        g_list_free(then_actions);
        return;
    }

    for (GList *iter = then_actions; iter != NULL; iter = iter->next) {
        pcmk_action_t *then_action_iter = (pcmk_action_t *) iter->data;

        if (first_action != NULL) {
            order_actions(first_action, then_action_iter, flags);
        } else {
            pcmk__clear_action_flags(then_action_iter, pcmk__action_runnable);
            crm_warn("%s of %s is unrunnable because there is no %s of %s "
                     "to order it after", then_action_iter->task, rsc->id,
                     order->task1, order->rsc1->id);
        }
    }

    g_list_free(then_actions);
}

static void
rsc_order_first(pcmk_resource_t *first_rsc, pcmk__action_relation_t *order)
{
    GList *first_actions = NULL;
    pcmk_action_t *first_action = order->action1;
    pcmk_resource_t *then_rsc = order->rsc2;

    pcmk__assert(first_rsc != NULL);
    pcmk__rsc_trace(first_rsc, "Applying ordering constraint %d (first: %s)",
                    order->id, first_rsc->id);

    if (first_action != NULL) {
        first_actions = g_list_prepend(NULL, first_action);

    } else {
        first_actions = find_actions_by_task(first_rsc, order->task1);
    }

    if ((first_actions == NULL) && (first_rsc == then_rsc)) {
        pcmk__rsc_trace(first_rsc,
                        "Ignoring constraint %d: first (%s for %s) not found",
                        order->id, order->task1, first_rsc->id);

    } else if (first_actions == NULL) {
        char *key = NULL;
        char *op_type = NULL;
        guint interval_ms = 0;
        enum rsc_role_e first_role;

        parse_op_key(order->task1, NULL, &op_type, &interval_ms);
        key = pcmk__op_key(first_rsc->id, op_type, interval_ms);

        first_role = first_rsc->priv->fns->state(first_rsc, true);
        if ((first_role == pcmk_role_stopped)
            && pcmk__str_eq(op_type, PCMK_ACTION_STOP, pcmk__str_none)) {
            free(key);
            pcmk__rsc_trace(first_rsc,
                            "Ignoring constraint %d: first (%s for %s) "
                            "not found",
                            order->id, order->task1, first_rsc->id);

        } else if ((first_role == pcmk_role_unpromoted)
                   && pcmk__str_eq(op_type, PCMK_ACTION_DEMOTE,
                                   pcmk__str_none)) {
            free(key);
            pcmk__rsc_trace(first_rsc,
                            "Ignoring constraint %d: first (%s for %s) "
                            "not found",
                            order->id, order->task1, first_rsc->id);

        } else {
            pcmk__rsc_trace(first_rsc,
                            "Creating first (%s for %s) for constraint %d ",
                            order->task1, first_rsc->id, order->id);
            first_action = custom_action(first_rsc, key, op_type, NULL, TRUE,
                                         first_rsc->priv->scheduler);
            first_actions = g_list_prepend(NULL, first_action);
        }

        free(op_type);
    }

    if (then_rsc == NULL) {
        if (order->action2 == NULL) {
            pcmk__rsc_trace(first_rsc, "Ignoring constraint %d: then not found",
                            order->id);
            return;
        }
        then_rsc = order->action2->rsc;
    }
    for (GList *iter = first_actions; iter != NULL; iter = iter->next) {
        first_action = iter->data;

        if (then_rsc == NULL) {
            order_actions(first_action, order->action2, order->flags);

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
    pcmk__update_action_for_orderings((pcmk_action_t *) data,
                                      (pcmk_scheduler_t *) user_data);
}

/*!
 * \internal
 * \brief Apply all ordering constraints
 *
 * \param[in,out] sched  Scheduler data
 */
void
pcmk__apply_orderings(pcmk_scheduler_t *sched)
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
    sched->priv->ordering_constraints =
        g_list_reverse(sched->priv->ordering_constraints);

    for (GList *iter = sched->priv->ordering_constraints;
         iter != NULL; iter = iter->next) {

        pcmk__action_relation_t *order = iter->data;
        pcmk_resource_t *rsc = order->rsc1;

        if (rsc != NULL) {
            rsc_order_first(rsc, order);
            continue;
        }

        rsc = order->rsc2;
        if (rsc != NULL) {
            order_resource_actions_after(order->action1, rsc, order);

        } else {
            crm_trace("Applying ordering constraint %d (non-resource actions)",
                      order->id);
            order_actions(order->action1, order->action2, order->flags);
        }
    }

    g_list_foreach(sched->priv->actions, block_colocation_dependents, NULL);

    crm_trace("Ordering probes");
    pcmk__order_probes(sched);

    crm_trace("Updating %d actions", g_list_length(sched->priv->actions));
    g_list_foreach(sched->priv->actions, update_action_for_orderings, sched);

    pcmk__disable_invalid_orderings(sched);
}

/*!
 * \internal
 * \brief Order a given action after each action in a given list
 *
 * \param[in,out] after  "After" action
 * \param[in,out] list   List of "before" actions
 */
void
pcmk__order_after_each(pcmk_action_t *after, GList *list)
{
    const char *after_desc = (after->task == NULL)? after->uuid : after->task;

    for (GList *iter = list; iter != NULL; iter = iter->next) {
        pcmk_action_t *before = (pcmk_action_t *) iter->data;
        const char *before_desc = before->task? before->task : before->uuid;

        crm_debug("Ordering %s on %s before %s on %s",
                  before_desc, pcmk__node_name(before->node),
                  after_desc, pcmk__node_name(after->node));
        order_actions(before, after, pcmk__ar_ordered);
    }
}

/*!
 * \internal
 * \brief Order promotions and demotions for restarts of a clone or bundle
 *
 * \param[in,out] rsc  Clone or bundle to order
 */
void
pcmk__promotable_restart_ordering(pcmk_resource_t *rsc)
{
    // Order start and promote after all instances are stopped
    pcmk__order_resource_actions(rsc, PCMK_ACTION_STOPPED,
                                 rsc, PCMK_ACTION_START,
                                 pcmk__ar_ordered);
    pcmk__order_resource_actions(rsc, PCMK_ACTION_STOPPED,
                                 rsc, PCMK_ACTION_PROMOTE,
                                 pcmk__ar_ordered);

    // Order stop, start, and promote after all instances are demoted
    pcmk__order_resource_actions(rsc, PCMK_ACTION_DEMOTED,
                                 rsc, PCMK_ACTION_STOP,
                                 pcmk__ar_ordered);
    pcmk__order_resource_actions(rsc, PCMK_ACTION_DEMOTED,
                                 rsc, PCMK_ACTION_START,
                                 pcmk__ar_ordered);
    pcmk__order_resource_actions(rsc, PCMK_ACTION_DEMOTED,
                                 rsc, PCMK_ACTION_PROMOTE,
                                 pcmk__ar_ordered);

    // Order promote after all instances are started
    pcmk__order_resource_actions(rsc, PCMK_ACTION_RUNNING,
                                 rsc, PCMK_ACTION_PROMOTE,
                                 pcmk__ar_ordered);

    // Order demote after all instances are demoted
    pcmk__order_resource_actions(rsc, PCMK_ACTION_DEMOTE,
                                 rsc, PCMK_ACTION_DEMOTED,
                                 pcmk__ar_ordered);
}

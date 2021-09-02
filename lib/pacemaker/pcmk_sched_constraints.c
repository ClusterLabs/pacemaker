/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <sys/types.h>
#include <stdbool.h>
#include <regex.h>
#include <glib.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>
#include <crm/common/iso8601.h>
#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>
#include <crm/pengine/rules.h>
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

#define EXPAND_CONSTRAINT_IDREF(__set, __rsc, __name) do {				\
	__rsc = pcmk__find_constraint_resource(data_set->resources, __name);		\
	if(__rsc == NULL) {						\
	    pcmk__config_err("%s: No resource found for %s", __set, __name);    \
	    return FALSE;						\
	}								\
    } while(0)

static void unpack_rsc_order(xmlNode *xml_obj, pe_working_set_t *data_set);

static bool
evaluate_lifetime(xmlNode *lifetime, pe_working_set_t *data_set)
{
    bool result = FALSE;
    crm_time_t *next_change = crm_time_new_undefined();

    result = pe_evaluate_rules(lifetime, NULL, data_set->now, next_change);
    if (crm_time_is_defined(next_change)) {
        time_t recheck = (time_t) crm_time_get_seconds_since_epoch(next_change);

        pe__update_recheck_time(recheck, data_set);
    }
    crm_time_free(next_change);
    return result;
}

gboolean
unpack_constraints(xmlNode * xml_constraints, pe_working_set_t * data_set)
{
    xmlNode *xml_obj = NULL;
    xmlNode *lifetime = NULL;

    for (xml_obj = pcmk__xe_first_child(xml_constraints); xml_obj != NULL;
         xml_obj = pcmk__xe_next(xml_obj)) {
        const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
        const char *tag = crm_element_name(xml_obj);

        if (id == NULL) {
            pcmk__config_err("Ignoring <%s> constraint without "
                             XML_ATTR_ID, tag);
            continue;
        }

        crm_trace("Unpacking %s constraint '%s'", tag, id);

        lifetime = first_named_child(xml_obj, "lifetime");
        if (lifetime) {
            pcmk__config_warn("Support for 'lifetime' attribute (in %s) is "
                              "deprecated (the rules it contains should "
                              "instead be direct descendents of the "
                              "constraint object)", id);
        }

        if (lifetime && !evaluate_lifetime(lifetime, data_set)) {
            crm_info("Constraint %s %s is not active", tag, id);

        } else if (pcmk__str_eq(XML_CONS_TAG_RSC_ORDER, tag, pcmk__str_casei)) {
            unpack_rsc_order(xml_obj, data_set);

        } else if (pcmk__str_eq(XML_CONS_TAG_RSC_DEPEND, tag, pcmk__str_casei)) {
            pcmk__unpack_colocation(xml_obj, data_set);

        } else if (pcmk__str_eq(XML_CONS_TAG_RSC_LOCATION, tag, pcmk__str_casei)) {
            pcmk__unpack_location(xml_obj, data_set);

        } else if (pcmk__str_eq(XML_CONS_TAG_RSC_TICKET, tag, pcmk__str_casei)) {
            pcmk__unpack_rsc_ticket(xml_obj, data_set);

        } else {
            pe_err("Unsupported constraint type: %s", tag);
        }
    }

    return TRUE;
}

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
get_ordering_type(xmlNode * xml_obj)
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
                         "and will be removed in a future release (use 'kind' instead)");
        }

    } else if (pcmk__str_eq(kind, "Mandatory", pcmk__str_casei)) {
        kind_e = pe_order_kind_mandatory;

    } else if (pcmk__str_eq(kind, "Optional", pcmk__str_casei)) {
        kind_e = pe_order_kind_optional;

    } else if (pcmk__str_eq(kind, "Serialize", pcmk__str_casei)) {
        kind_e = pe_order_kind_serialize;

    } else {
        pcmk__config_err("Resetting '" XML_ORDER_ATTR_KIND "' for constraint "
                         "'%s' to Mandatory because '%s' is not valid",
                         crm_str(ID(xml_obj)), kind);
    }
    return kind_e;
}

pe_resource_t *
pcmk__find_constraint_resource(GList *rsc_list, const char *id)
{
    GList *rIter = NULL;

    for (rIter = rsc_list; id && rIter; rIter = rIter->next) {
        pe_resource_t *parent = rIter->data;
        pe_resource_t *match = parent->fns->find_rsc(parent, id, NULL,
                                                     pe_find_renamed);

        if (match != NULL) {
            if(!pcmk__str_eq(match->id, id, pcmk__str_casei)) {
                /* We found an instance of a clone instead */
                match = uber_parent(match);
                crm_debug("Found %s for %s", match->id, id);
            }
            return match;
        }
    }
    crm_trace("No match for %s", id);
    return NULL;
}

static gboolean
pe_find_constraint_tag(pe_working_set_t * data_set, const char * id, pe_tag_t ** tag)
{
    gboolean rc = FALSE;

    *tag = NULL;
    rc = g_hash_table_lookup_extended(data_set->template_rsc_sets, id,
                                       NULL, (gpointer*) tag);

    if (rc == FALSE) {
        rc = g_hash_table_lookup_extended(data_set->tags, id,
                                          NULL, (gpointer*) tag);

        if (rc == FALSE) {
            crm_warn("No template or tag named '%s'", id);
            return FALSE;

        } else if (*tag == NULL) {
            crm_warn("No resource is tagged with '%s'", id);
            return FALSE;
        }

    } else if (*tag == NULL) {
        crm_warn("No resource is derived from template '%s'", id);
        return FALSE;
    }

    return rc;
}

gboolean
pcmk__valid_resource_or_tag(pe_working_set_t *data_set, const char *id,
                            pe_resource_t **rsc, pe_tag_t **tag)
{
    gboolean rc = FALSE;

    if (rsc) {
        *rsc = NULL;
        *rsc = pcmk__find_constraint_resource(data_set->resources, id);
        if (*rsc) {
            return TRUE;
        }
    }

    if (tag) {
        *tag = NULL;
        rc = pe_find_constraint_tag(data_set, id, tag);
    }

    return rc;
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
get_ordering_symmetry(xmlNode *xml_obj, enum pe_order_kind parent_kind,
                      const char *parent_symmetrical_s)
{
    const char *symmetrical_s = NULL;
    enum pe_order_kind kind = parent_kind; // Default to parent's kind

    // Check ordering XML for explicit kind
    if ((crm_element_value(xml_obj, XML_ORDER_ATTR_KIND) != NULL)
        || (crm_element_value(xml_obj, XML_RULE_ATTR_SCORE) != NULL)) {
        kind = get_ordering_type(xml_obj);
    }

    // Check ordering XML (and parent) for explicit symmetrical setting
    symmetrical_s = crm_element_value(xml_obj, XML_CONS_ATTR_SYMMETRICAL);
    if (symmetrical_s == NULL) {
        symmetrical_s = parent_symmetrical_s;
    }
    if (symmetrical_s != NULL) {
        if (crm_is_true(symmetrical_s)) {
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
static enum pe_ordering
ordering_flags_for_kind(enum pe_order_kind kind, const char *first,
                        enum ordering_symmetry symmetry)
{
    enum pe_ordering flags = pe_order_none; // so we trace-log all flags set

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
 * \param[in] instance_attr  XML attribute name for instance number
 * \param[in] data_set       Cluster working set
 *
 * \return Resource corresponding to \p id, or NULL if none
 */
static pe_resource_t *
get_ordering_resource(xmlNode *xml, const char *resource_attr,
                      const char *instance_attr, pe_working_set_t *data_set)
{
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
        if (!pe_rsc_is_clone(rsc)) {
            pcmk__config_err("Ignoring constraint '%s' because resource '%s' "
                             "is not a clone but instance '%s' was requested",
                             ID(xml), rsc_id, instance_id);
            return NULL;
        }
        rsc = find_clone_instance(rsc, instance_id, data_set);
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
get_minimum_first_instances(pe_resource_t *rsc, xmlNode *xml)
{
    if (pe_rsc_is_clone(rsc)) {
        const char *clone_min = NULL;

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
        clone_min = crm_element_value(xml, "require-all");
        if (clone_min != NULL) {
            pe_warn_once(pe_wo_require_all,
                         "Support for require-all in ordering constraints "
                         "is deprecated and will be removed in a future release"
                         " (use clone-min clone meta-attribute instead)");
            if (!crm_is_true(clone_min)) {
                return 1;
            }
        }
    }
    return 0;
}

/*!
 * \internal
 * \brief Create orderings for a constraint with clone-min > 0
 *
 * \param[in] id            Ordering ID
 * \param[in] rsc_first     'First' resource in ordering (a clone)
 * \param[in] action_first  'First' action in ordering
 * \param[in] rsc_then      'Then' resource in ordering
 * \param[in] action_then   'Then' action in ordering
 * \param[in] flags         Ordering flags
 * \param[in] clone_min     Minimum required instances of 'first'
 * \param[in] data_set      Cluster working set
 */
static void
clone_min_ordering(const char *id,
                   pe_resource_t *rsc_first, const char *action_first,
                   pe_resource_t *rsc_then, const char *action_then,
                   enum pe_ordering flags, int clone_min,
                   pe_working_set_t *data_set)
{
    // Create a pseudo-action for when the minimum instances are active
    char *task = crm_strdup_printf(CRM_OP_RELAXED_CLONE ":%s", id);
    pe_action_t *clone_min_met = get_pseudo_op(task, data_set);

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
                            data_set);
    }

    // Order "then" action after the pseudo-action (if runnable)
    pcmk__new_ordering(NULL, NULL, clone_min_met, rsc_then,
                        pcmk__op_key(rsc_then->id, action_then, 0),
                        NULL, flags|pe_order_runnable_left, data_set);
}

/*!
 * \internal
 * \brief Update ordering flags for restart-type=restart
 *
 * \param[in]  rsc    'Then' resource in ordering
 * \param[in]  kind   Ordering kind
 * \param[in]  flag   Ordering flag to set (when applicable)
 * \param[out] flags  Ordering flag set to update
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
 * \param[in] id            Ordering ID (for logging only)
 * \param[in] kind          Ordering kind
 * \param[in] rsc_first     'First' resource in ordering (a clone)
 * \param[in] action_first  'First' action in ordering
 * \param[in] rsc_then      'Then' resource in ordering
 * \param[in] action_then   'Then' action in ordering
 * \param[in] data_set      Cluster working set
 */
static void
inverse_ordering(const char *id, enum pe_order_kind kind,
                 pe_resource_t *rsc_first, const char *action_first,
                 pe_resource_t *rsc_then, const char *action_then,
                 pe_working_set_t *data_set)
{
    action_then = invert_action(action_then);
    action_first = invert_action(action_first);
    if ((action_then == NULL) || (action_first == NULL)) {
        pcmk__config_warn("Cannot invert constraint '%s' "
                          "(please specify inverse manually)", id);
    } else {
        enum pe_ordering flags = ordering_flags_for_kind(kind, action_first,
                                                         ordering_symmetric_inverse);

        handle_restart_type(rsc_then, kind, pe_order_implies_first, flags);
        pcmk__order_resource_actions(rsc_then, action_then, rsc_first, action_first, flags,
                      data_set);
    }
}

static void
unpack_simple_rsc_order(xmlNode * xml_obj, pe_working_set_t * data_set)
{
    pe_resource_t *rsc_then = NULL;
    pe_resource_t *rsc_first = NULL;
    int min_required_before = 0;
    enum pe_order_kind kind = pe_order_kind_mandatory;
    enum pe_ordering cons_weight = pe_order_none;
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
    cons_weight = ordering_flags_for_kind(kind, action_first, symmetry);

    handle_restart_type(rsc_then, kind, pe_order_implies_then, cons_weight);

    /* If there is a minimum number of instances that must be runnable before
     * the 'then' action is runnable, we use a pseudo-action for convenience:
     * minimum number of clone instances have runnable actions ->
     * pseudo-action is runnable -> dependency is runnable.
     */
    min_required_before = get_minimum_first_instances(rsc_first, xml_obj);
    if (min_required_before > 0) {
        clone_min_ordering(id, rsc_first, action_first, rsc_then, action_then,
                           cons_weight, min_required_before, data_set);
    } else {
        pcmk__order_resource_actions(rsc_first, action_first, rsc_then, action_then,
                      cons_weight, data_set);
    }

    if (symmetry == ordering_symmetric) {
        inverse_ordering(id, kind, rsc_first, action_first,
                         rsc_then, action_then, data_set);
    }
}

/*!
 * \internal
 * \brief Replace any resource tags with equivalent resource_ref entries
 *
 * If a given constraint has resource sets, check each set for resource_ref
 * entries that list tags rather than resource IDs, and replace any found with
 * resource_ref entries for the corresponding resource IDs.
 *
 * \param[in]  xml_obj       Constraint XML
 * \param[in]  data_set      Cluster working set
 *
 * \return Equivalent XML with resource tags replaced (or NULL if none)
 * \note It is the caller's responsibility to free the result with free_xml().
 */
xmlNode *
pcmk__expand_tags_in_sets(xmlNode *xml_obj, pe_working_set_t *data_set)
{
    xmlNode *new_xml = NULL;
    bool any_refs = false;

    // Short-circuit if there are no sets
    if (first_named_child(xml_obj, XML_CONS_TAG_RSC_SET) == NULL) {
        return NULL;
    }

    new_xml = copy_xml(xml_obj);

    for (xmlNode *set = first_named_child(new_xml, XML_CONS_TAG_RSC_SET);
         set != NULL; set = crm_next_same_xml(set)) {

        GList *tag_refs = NULL;
        GList *gIter = NULL;

        for (xmlNode *xml_rsc = first_named_child(set, XML_TAG_RESOURCE_REF);
             xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

            pe_resource_t *rsc = NULL;
            pe_tag_t *tag = NULL;

            if (!pcmk__valid_resource_or_tag(data_set, ID(xml_rsc), &rsc,
                                             &tag)) {
                pcmk__config_err("Ignoring resource sets for constraint '%s' "
                                 "because '%s' is not a valid resource or tag",
                                 ID(xml_obj), ID(xml_rsc));
                free_xml(new_xml);
                return NULL;

            } else if (rsc) {
                continue;

            } else if (tag) {
                /* The resource_ref under the resource_set references a template/tag */
                xmlNode *last_ref = xml_rsc;

                /* A sample:

                   Original XML:

                   <resource_set id="tag1-colocation-0" sequential="true">
                     <resource_ref id="rsc1"/>
                     <resource_ref id="tag1"/>
                     <resource_ref id="rsc4"/>
                   </resource_set>

                   Now we are appending rsc2 and rsc3 which are tagged with tag1 right after it:

                   <resource_set id="tag1-colocation-0" sequential="true">
                     <resource_ref id="rsc1"/>
                     <resource_ref id="tag1"/>
                     <resource_ref id="rsc2"/>
                     <resource_ref id="rsc3"/>
                     <resource_ref id="rsc4"/>
                   </resource_set>

                 */

                for (gIter = tag->refs; gIter != NULL; gIter = gIter->next) {
                    const char *obj_ref = (const char *) gIter->data;
                    xmlNode *new_rsc_ref = NULL;

                    new_rsc_ref = xmlNewDocRawNode(getDocPtr(set), NULL,
                                                   (pcmkXmlStr) XML_TAG_RESOURCE_REF, NULL);
                    crm_xml_add(new_rsc_ref, XML_ATTR_ID, obj_ref);
                    xmlAddNextSibling(last_ref, new_rsc_ref);

                    last_ref = new_rsc_ref;
                }

                any_refs = true;

                /* Freeing the resource_ref now would break the XML child
                 * iteration, so just remember it for freeing later.
                 */
                tag_refs = g_list_append(tag_refs, xml_rsc);
            }
        }

        /* Now free '<resource_ref id="tag1"/>', and finally get:

           <resource_set id="tag1-colocation-0" sequential="true">
             <resource_ref id="rsc1"/>
             <resource_ref id="rsc2"/>
             <resource_ref id="rsc3"/>
             <resource_ref id="rsc4"/>
           </resource_set>

         */
        for (gIter = tag_refs; gIter != NULL; gIter = gIter->next) {
            xmlNode *tag_ref = gIter->data;

            free_xml(tag_ref);
        }
        g_list_free(tag_refs);
    }

    if (!any_refs) {
        free_xml(new_xml);
        new_xml = NULL;
    }
    return new_xml;
}

gboolean
pcmk__tag_to_set(xmlNode *xml_obj, xmlNode **rsc_set, const char *attr,
                 gboolean convert_rsc, pe_working_set_t *data_set)
{
    const char *cons_id = NULL;
    const char *id = NULL;

    pe_resource_t *rsc = NULL;
    pe_tag_t *tag = NULL;

    *rsc_set = NULL;

    CRM_CHECK((xml_obj != NULL) && (attr != NULL), return FALSE);

    cons_id = ID(xml_obj);
    if (cons_id == NULL) {
        pcmk__config_err("Ignoring <%s> constraint without " XML_ATTR_ID,
                         crm_element_name(xml_obj));
        return FALSE;
    }

    id = crm_element_value(xml_obj, attr);
    if (id == NULL) {
        return TRUE;
    }

    if (!pcmk__valid_resource_or_tag(data_set, id, &rsc, &tag)) {
        pcmk__config_err("Ignoring constraint '%s' because '%s' is not a "
                         "valid resource or tag", cons_id, id);
        return FALSE;

    } else if (tag) {
        GList *gIter = NULL;

        /* A template/tag is referenced by the "attr" attribute (first, then, rsc or with-rsc).
           Add the template/tag's corresponding "resource_set" which contains the resources derived
           from it or tagged with it under the constraint. */
        *rsc_set = create_xml_node(xml_obj, XML_CONS_TAG_RSC_SET);
        crm_xml_add(*rsc_set, XML_ATTR_ID, id);

        for (gIter = tag->refs; gIter != NULL; gIter = gIter->next) {
            const char *obj_ref = (const char *) gIter->data;
            xmlNode *rsc_ref = NULL;

            rsc_ref = create_xml_node(*rsc_set, XML_TAG_RESOURCE_REF);
            crm_xml_add(rsc_ref, XML_ATTR_ID, obj_ref);
        }

        /* Set sequential="false" for the resource_set */
        crm_xml_add(*rsc_set, "sequential", XML_BOOLEAN_FALSE);

    } else if (rsc && convert_rsc) {
        /* Even a regular resource is referenced by "attr", convert it into a resource_set.
           Because the other side of the constraint could be a template/tag reference. */
        xmlNode *rsc_ref = NULL;

        *rsc_set = create_xml_node(xml_obj, XML_CONS_TAG_RSC_SET);
        crm_xml_add(*rsc_set, XML_ATTR_ID, id);

        rsc_ref = create_xml_node(*rsc_set, XML_TAG_RESOURCE_REF);
        crm_xml_add(rsc_ref, XML_ATTR_ID, id);

    } else {
        return TRUE;
    }

    /* Remove the "attr" attribute referencing the template/tag */
    if (*rsc_set) {
        xml_remove_prop(xml_obj, attr);
    }

    return TRUE;
}

static char *
task_from_action_or_key(pe_action_t *action, const char *key)
{
    char *res = NULL;

    if (action) {
        res = strdup(action->task);
    } else if (key) {
        parse_op_key(key, NULL, &res, NULL);
    }
    return res;
}

/* when order constraints are made between two resources start and stop actions
 * those constraints have to be mirrored against the corresponding
 * migration actions to ensure start/stop ordering is preserved during
 * a migration */
static void
handle_migration_ordering(pe__ordering_t *order, pe_working_set_t *data_set)
{
    char *lh_task = NULL;
    char *rh_task = NULL;
    gboolean rh_migratable;
    gboolean lh_migratable;

    if (order->lh_rsc == NULL || order->rh_rsc == NULL) {
        return;
    } else if (order->lh_rsc == order->rh_rsc) {
        return;
    /* don't mess with those constraints built between parent
     * resources and the children */
    } else if (is_parent(order->lh_rsc, order->rh_rsc)) {
        return;
    } else if (is_parent(order->rh_rsc, order->lh_rsc)) {
        return;
    }

    lh_migratable = pcmk_is_set(order->lh_rsc->flags, pe_rsc_allow_migrate);
    rh_migratable = pcmk_is_set(order->rh_rsc->flags, pe_rsc_allow_migrate);

    /* one of them has to be migratable for
     * the migrate ordering logic to be applied */
    if (lh_migratable == FALSE && rh_migratable == FALSE) {
        return;
    }

    /* at this point we have two resources which allow migrations that have an
     * order dependency set between them.  If those order dependencies involve
     * start/stop actions, we need to mirror the corresponding migrate actions
     * so order will be preserved. */
    lh_task = task_from_action_or_key(order->lh_action, order->lh_action_task);
    rh_task = task_from_action_or_key(order->rh_action, order->rh_action_task);
    if (lh_task == NULL || rh_task == NULL) {
        goto cleanup_order;
    }

    if (pcmk__str_eq(lh_task, RSC_START, pcmk__str_casei) && pcmk__str_eq(rh_task, RSC_START, pcmk__str_casei)) {
        int flags = pe_order_optional;

        if (lh_migratable && rh_migratable) {
            /* A start then B start
             * A migrate_from then B migrate_to */
            pcmk__new_ordering(order->lh_rsc,
                                pcmk__op_key(order->lh_rsc->id, RSC_MIGRATED, 0),
                                NULL, order->rh_rsc,
                                pcmk__op_key(order->rh_rsc->id, RSC_MIGRATE, 0),
                                NULL, flags, data_set);
        }

        if (rh_migratable) {
            if (lh_migratable) {
                pe__set_order_flags(flags, pe_order_apply_first_non_migratable);
            }

            /* A start then B start
             * A start then B migrate_to... only if A start is not a part of a migration*/
            pcmk__new_ordering(order->lh_rsc,
                                pcmk__op_key(order->lh_rsc->id, RSC_START, 0),
                                NULL, order->rh_rsc,
                                pcmk__op_key(order->rh_rsc->id, RSC_MIGRATE, 0),
                                NULL, flags, data_set);
        }

    } else if (rh_migratable == TRUE && pcmk__str_eq(lh_task, RSC_STOP, pcmk__str_casei) && pcmk__str_eq(rh_task, RSC_STOP, pcmk__str_casei)) {
        int flags = pe_order_optional;

        if (lh_migratable) {
            pe__set_order_flags(flags, pe_order_apply_first_non_migratable);
        }

        /* rh side is at the bottom of the stack during a stop. If we have a constraint
         * stop B then stop A, if B is migrating via stop/start, and A is migrating using migration actions,
         * we need to enforce that A's migrate_to action occurs after B's stop action. */
        pcmk__new_ordering(order->lh_rsc,
                            pcmk__op_key(order->lh_rsc->id, RSC_STOP, 0), NULL,
                            order->rh_rsc,
                            pcmk__op_key(order->rh_rsc->id, RSC_MIGRATE, 0),
                            NULL, flags, data_set);

        /* We need to build the stop constraint against migrate_from as well
         * to account for partial migrations. */
        if (order->rh_rsc->partial_migration_target) {
            pcmk__new_ordering(order->lh_rsc,
                                pcmk__op_key(order->lh_rsc->id, RSC_STOP, 0),
                                NULL, order->rh_rsc,
                                pcmk__op_key(order->rh_rsc->id, RSC_MIGRATED, 0),
                                NULL, flags, data_set);
        }

    } else if (pcmk__str_eq(lh_task, RSC_PROMOTE, pcmk__str_casei) && pcmk__str_eq(rh_task, RSC_START, pcmk__str_casei)) {
        int flags = pe_order_optional;

        if (rh_migratable) {
            /* A promote then B start
             * A promote then B migrate_to */
            pcmk__new_ordering(order->lh_rsc,
                                pcmk__op_key(order->lh_rsc->id, RSC_PROMOTE, 0),
                                NULL, order->rh_rsc,
                                pcmk__op_key(order->rh_rsc->id, RSC_MIGRATE, 0),
                                NULL, flags, data_set);
        }

    } else if (pcmk__str_eq(lh_task, RSC_DEMOTE, pcmk__str_casei) && pcmk__str_eq(rh_task, RSC_STOP, pcmk__str_casei)) {
        int flags = pe_order_optional;

        if (rh_migratable) {
            /* A demote then B stop
             * A demote then B migrate_to */
            pcmk__new_ordering(order->lh_rsc, pcmk__op_key(order->lh_rsc->id, RSC_DEMOTE, 0), NULL,
                                order->rh_rsc, pcmk__op_key(order->rh_rsc->id, RSC_MIGRATE, 0), NULL,
                                flags, data_set);

            /* We need to build the demote constraint against migrate_from as well
             * to account for partial migrations. */
            if (order->rh_rsc->partial_migration_target) {
                pcmk__new_ordering(order->lh_rsc,
                                    pcmk__op_key(order->lh_rsc->id, RSC_DEMOTE, 0),
                                    NULL, order->rh_rsc,
                                    pcmk__op_key(order->rh_rsc->id, RSC_MIGRATED, 0),
                                    NULL, flags, data_set);
            }
        }
    }

cleanup_order:
    free(lh_task);
    free(rh_task);
}

/* LHS before RHS */
void
pcmk__new_ordering(pe_resource_t *lh_rsc, char *lh_action_task, pe_action_t *lh_action,
                    pe_resource_t * rh_rsc, char *rh_action_task, pe_action_t * rh_action,
                    enum pe_ordering type, pe_working_set_t * data_set)
{
    pe__ordering_t *order = NULL;

    // One of action or resource must be specified for each side
    CRM_CHECK(((lh_action != NULL) || (lh_rsc != NULL))
              && ((rh_action != NULL) || (rh_rsc != NULL)),
              free(lh_action_task); free(rh_action_task); return);

    if (lh_rsc == NULL && lh_action) {
        lh_rsc = lh_action->rsc;
    }
    if (rh_rsc == NULL && rh_action) {
        rh_rsc = rh_action->rsc;
    }

    order = calloc(1, sizeof(pe__ordering_t));

    order->id = data_set->order_id++;
    order->type = type;
    order->lh_rsc = lh_rsc;
    order->rh_rsc = rh_rsc;
    order->lh_action = lh_action;
    order->rh_action = rh_action;
    order->lh_action_task = lh_action_task;
    order->rh_action_task = rh_action_task;

    if (order->lh_action_task == NULL && lh_action) {
        order->lh_action_task = strdup(lh_action->uuid);
    }

    if (order->rh_action_task == NULL && rh_action) {
        order->rh_action_task = strdup(rh_action->uuid);
    }

    if (order->lh_rsc == NULL && lh_action) {
        order->lh_rsc = lh_action->rsc;
    }

    if (order->rh_rsc == NULL && rh_action) {
        order->rh_rsc = rh_action->rsc;
    }

    pe_rsc_trace(lh_rsc, "Created ordering %d for %s then %s",
                 (data_set->order_id - 1),
                 ((lh_action_task == NULL)? "?" : lh_action_task),
                 ((rh_action_task == NULL)? "?" : rh_action_task));

    data_set->ordering_constraints = g_list_prepend(data_set->ordering_constraints, order);
    handle_migration_ordering(order, data_set);
}

static gboolean
unpack_order_set(xmlNode * set, enum pe_order_kind parent_kind, pe_resource_t ** rsc,
                 const char *parent_symmetrical_s,
                 pe_working_set_t * data_set)
{
    xmlNode *xml_rsc = NULL;
    GList *set_iter = NULL;
    GList *resources = NULL;

    pe_resource_t *last = NULL;
    pe_resource_t *resource = NULL;

    int local_kind = parent_kind;
    gboolean sequential = FALSE;
    enum pe_ordering flags = pe_order_optional;
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

    for (xml_rsc = first_named_child(set, XML_TAG_RESOURCE_REF);
         xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

        EXPAND_CONSTRAINT_IDREF(id, resource, ID(xml_rsc));
        resources = g_list_append(resources, resource);
    }

    if (pcmk__list_of_1(resources)) {
        crm_trace("Single set: %s", id);
        *rsc = resource;
        goto done;
    }

    *rsc = NULL;

    set_iter = resources;
    while (set_iter != NULL) {
        resource = (pe_resource_t *) set_iter->data;
        set_iter = set_iter->next;

        key = pcmk__op_key(resource->id, action, 0);

        if (local_kind == pe_order_kind_serialize) {
            /* Serialize before everything that comes after */

            GList *gIter = NULL;

            for (gIter = set_iter; gIter != NULL; gIter = gIter->next) {
                pe_resource_t *then_rsc = (pe_resource_t *) gIter->data;
                char *then_key = pcmk__op_key(then_rsc->id, action, 0);

                pcmk__new_ordering(resource, strdup(key), NULL, then_rsc, then_key, NULL,
                                    flags, data_set);
            }

        } else if (sequential) {
            if (last != NULL) {
                pcmk__order_resource_actions(last, action, resource, action, flags, data_set);
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
                pcmk__order_resource_actions(resource, action, last, action, flags, data_set);
            }
            last = resource;
        }
    }

  done:
    g_list_free(resources);
    return TRUE;
}

static gboolean
order_rsc_sets(const char *id, xmlNode * set1, xmlNode * set2, enum pe_order_kind kind,
               pe_working_set_t *data_set, enum ordering_symmetry symmetry)
{

    xmlNode *xml_rsc = NULL;
    xmlNode *xml_rsc_2 = NULL;

    pe_resource_t *rsc_1 = NULL;
    pe_resource_t *rsc_2 = NULL;

    const char *action_1 = crm_element_value(set1, "action");
    const char *action_2 = crm_element_value(set2, "action");

    const char *sequential_1 = crm_element_value(set1, "sequential");
    const char *sequential_2 = crm_element_value(set2, "sequential");

    const char *require_all_s = crm_element_value(set1, "require-all");
    gboolean require_all = require_all_s ? crm_is_true(require_all_s) : TRUE;

    enum pe_ordering flags = pe_order_none;

    if (action_1 == NULL) {
        action_1 = RSC_START;
    };

    if (action_2 == NULL) {
        action_2 = RSC_START;
    };

    if (symmetry == ordering_symmetric_inverse) {
        action_1 = invert_action(action_1);
        action_2 = invert_action(action_2);
    }

    if(pcmk__str_eq(RSC_STOP, action_1, pcmk__str_casei) || pcmk__str_eq(RSC_DEMOTE, action_1, pcmk__str_casei)) {
        /* Assuming: A -> ( B || C) -> D
         * The one-or-more logic only applies during the start/promote phase
         * During shutdown neither B nor can shutdown until D is down, so simply turn require_all back on.
         */
        require_all = TRUE;
    }

    // @TODO is action_2 correct here?
    flags = ordering_flags_for_kind(kind, action_2, symmetry);

    /* If we have an un-ordered set1, whether it is sequential or not is irrelevant in regards to set2. */
    if (!require_all) {
        char *task = crm_strdup_printf(CRM_OP_RELAXED_SET ":%s", ID(set1));
        pe_action_t *unordered_action = get_pseudo_op(task, data_set);

        free(task);
        pe__set_action_flags(unordered_action, pe_action_requires_any);

        for (xml_rsc = first_named_child(set1, XML_TAG_RESOURCE_REF);
             xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

            EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));

            /* Add an ordering constraint between every element in set1 and the pseudo action.
             * If any action in set1 is runnable the pseudo action will be runnable. */
            pcmk__new_ordering(rsc_1, pcmk__op_key(rsc_1->id, action_1, 0),
                                NULL, NULL, NULL, unordered_action,
                                pe_order_one_or_more|pe_order_implies_then_printed,
                                data_set);
        }
        for (xml_rsc_2 = first_named_child(set2, XML_TAG_RESOURCE_REF);
             xml_rsc_2 != NULL; xml_rsc_2 = crm_next_same_xml(xml_rsc_2)) {

            EXPAND_CONSTRAINT_IDREF(id, rsc_2, ID(xml_rsc_2));

            /* Add an ordering constraint between the pseudo action and every element in set2.
             * If the pseudo action is runnable, every action in set2 will be runnable */
            pcmk__new_ordering(NULL, NULL, unordered_action,
                                rsc_2, pcmk__op_key(rsc_2->id, action_2, 0),
                                NULL, flags|pe_order_runnable_left, data_set);
        }

        return TRUE;
    }

    if (crm_is_true(sequential_1)) {
        if (symmetry == ordering_symmetric_inverse) {
            /* get the first one */
            xml_rsc = first_named_child(set1, XML_TAG_RESOURCE_REF);
            if (xml_rsc != NULL) {
                EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));
            }

        } else {
            /* get the last one */
            const char *rid = NULL;

            for (xml_rsc = first_named_child(set1, XML_TAG_RESOURCE_REF);
                 xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {
                rid = ID(xml_rsc);
            }
            EXPAND_CONSTRAINT_IDREF(id, rsc_1, rid);
        }
    }

    if (crm_is_true(sequential_2)) {
        if (symmetry == ordering_symmetric_inverse) {
            /* get the last one */
            const char *rid = NULL;

            for (xml_rsc = first_named_child(set2, XML_TAG_RESOURCE_REF);
                 xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

                rid = ID(xml_rsc);
            }
            EXPAND_CONSTRAINT_IDREF(id, rsc_2, rid);

        } else {
            /* get the first one */
            xml_rsc = first_named_child(set2, XML_TAG_RESOURCE_REF);
            if (xml_rsc != NULL) {
                EXPAND_CONSTRAINT_IDREF(id, rsc_2, ID(xml_rsc));
            }
        }
    }

    if (rsc_1 != NULL && rsc_2 != NULL) {
        pcmk__order_resource_actions(rsc_1, action_1, rsc_2, action_2, flags, data_set);

    } else if (rsc_1 != NULL) {
        for (xml_rsc = first_named_child(set2, XML_TAG_RESOURCE_REF);
             xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

            EXPAND_CONSTRAINT_IDREF(id, rsc_2, ID(xml_rsc));
            pcmk__order_resource_actions(rsc_1, action_1, rsc_2, action_2, flags, data_set);
        }

    } else if (rsc_2 != NULL) {
        xmlNode *xml_rsc = NULL;

        for (xml_rsc = first_named_child(set1, XML_TAG_RESOURCE_REF);
             xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

            EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));
            pcmk__order_resource_actions(rsc_1, action_1, rsc_2, action_2, flags, data_set);
        }

    } else {
        for (xml_rsc = first_named_child(set1, XML_TAG_RESOURCE_REF);
             xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

            xmlNode *xml_rsc_2 = NULL;

            EXPAND_CONSTRAINT_IDREF(id, rsc_1, ID(xml_rsc));

            for (xml_rsc_2 = first_named_child(set2, XML_TAG_RESOURCE_REF);
                 xml_rsc_2 != NULL; xml_rsc_2 = crm_next_same_xml(xml_rsc_2)) {

                EXPAND_CONSTRAINT_IDREF(id, rsc_2, ID(xml_rsc_2));
                pcmk__order_resource_actions(rsc_1, action_1, rsc_2, action_2, flags, data_set);
            }
        }
    }

    return TRUE;
}

/*!
 * \internal
 * \brief If an ordering constraint uses resource tags, expand them
 *
 * \param[in]  xml_obj       Ordering constraint XML
 * \param[out] expanded_xml  Equivalent XML with tags expanded
 * \param[in]  data_set      Cluster working set
 *
 * \return Standard Pacemaker return code (specifically, pcmk_rc_ok on success,
 *         and pcmk_rc_schema_validation on invalid configuration)
 */
static int
unpack_order_tags(xmlNode *xml_obj, xmlNode **expanded_xml,
                  pe_working_set_t *data_set)
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
    gboolean any_sets = FALSE;

    // Check whether there are any resource sets with template or tag references
    *expanded_xml = pcmk__expand_tags_in_sets(xml_obj, data_set);
    if (*expanded_xml != NULL) {
        crm_log_xml_trace(*expanded_xml, "Expanded rsc_order");
        return pcmk_rc_ok;
    }

    id_first = crm_element_value(xml_obj, XML_ORDER_ATTR_FIRST);
    id_then = crm_element_value(xml_obj, XML_ORDER_ATTR_THEN);
    if (id_first == NULL || id_then == NULL) {
        return pcmk_rc_ok;
    }

    if (!pcmk__valid_resource_or_tag(data_set, id_first, &rsc_first, &tag_first)) {
        pcmk__config_err("Ignoring constraint '%s' because '%s' is not a "
                         "valid resource or tag", ID(xml_obj), id_first);
        return pcmk_rc_schema_validation;
    }

    if (!pcmk__valid_resource_or_tag(data_set, id_then, &rsc_then, &tag_then)) {
        pcmk__config_err("Ignoring constraint '%s' because '%s' is not a "
                         "valid resource or tag", ID(xml_obj), id_then);
        return pcmk_rc_schema_validation;
    }

    if (rsc_first && rsc_then) {
        /* Neither side references any template/tag. */
        return pcmk_rc_ok;
    }

    action_first = crm_element_value(xml_obj, XML_ORDER_ATTR_FIRST_ACTION);
    action_then = crm_element_value(xml_obj, XML_ORDER_ATTR_THEN_ACTION);

    *expanded_xml = copy_xml(xml_obj);

    /* Convert the template/tag reference in "first" into a resource_set under the order constraint. */
    if (!pcmk__tag_to_set(*expanded_xml, &rsc_set_first, XML_ORDER_ATTR_FIRST,
                          TRUE, data_set)) {
        free_xml(*expanded_xml);
        *expanded_xml = NULL;
        return pcmk_rc_schema_validation;
    }

    if (rsc_set_first) {
        if (action_first) {
            /* A "first-action" is specified.
               Move it into the converted resource_set as an "action" attribute. */
            crm_xml_add(rsc_set_first, "action", action_first);
            xml_remove_prop(*expanded_xml, XML_ORDER_ATTR_FIRST_ACTION);
        }
        any_sets = TRUE;
    }

    /* Convert the template/tag reference in "then" into a resource_set under the order constraint. */
    if (!pcmk__tag_to_set(*expanded_xml, &rsc_set_then, XML_ORDER_ATTR_THEN,
                          TRUE, data_set)) {
        free_xml(*expanded_xml);
        *expanded_xml = NULL;
        return pcmk_rc_schema_validation;
    }

    if (rsc_set_then) {
        if (action_then) {
            /* A "then-action" is specified.
               Move it into the converted resource_set as an "action" attribute. */
            crm_xml_add(rsc_set_then, "action", action_then);
            xml_remove_prop(*expanded_xml, XML_ORDER_ATTR_THEN_ACTION);
        }
        any_sets = TRUE;
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
 * \param[in]     xml_obj   Ordering constraint XML to unpack
 * \param[in,out] data_set  Cluster working set
 */
static void
unpack_rsc_order(xmlNode *xml_obj, pe_working_set_t *data_set)
{
    pe_resource_t *rsc = NULL;

    xmlNode *set = NULL;
    xmlNode *last = NULL;

    xmlNode *orig_xml = NULL;
    xmlNode *expanded_xml = NULL;

    const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
    const char *invert = crm_element_value(xml_obj, XML_CONS_ATTR_SYMMETRICAL);
    enum pe_order_kind kind = get_ordering_type(xml_obj);

    enum ordering_symmetry symmetry = get_ordering_symmetry(xml_obj, kind, NULL);

    // Expand any resource tags in the constraint XML
    if (unpack_order_tags(xml_obj, &expanded_xml, data_set) != pcmk_rc_ok) {
        return;
    }
    if (expanded_xml != NULL) {
        orig_xml = xml_obj;
        xml_obj = expanded_xml;
    }

    // If the constraint has resource sets, unpack them
    for (set = first_named_child(xml_obj, XML_CONS_TAG_RSC_SET); set != NULL;
         set = crm_next_same_xml(set)) {

        set = expand_idref(set, data_set->input);
        if ((set == NULL) // Configuration error, message already logged
            || !unpack_order_set(set, kind, &rsc, invert, data_set)) {
            if (expanded_xml != NULL) {
                free_xml(expanded_xml);
            }
            return;
        }

        if ((last != NULL)
            && (!order_rsc_sets(id, last, set, kind, data_set, symmetry)
                || ((symmetry == ordering_symmetric)
                    && !order_rsc_sets(id, set, last, kind, data_set,
                                       ordering_symmetric_inverse)))) {
            if (expanded_xml != NULL) {
                free_xml(expanded_xml);
            }
            return;
        }
        last = set;
    }

    if (expanded_xml) {
        free_xml(expanded_xml);
        xml_obj = orig_xml;
    }

    // If the constraint has no resource sets, unpack it as a simple ordering
    if (last == NULL) {
        unpack_simple_rsc_order(xml_obj, data_set);
    }
}

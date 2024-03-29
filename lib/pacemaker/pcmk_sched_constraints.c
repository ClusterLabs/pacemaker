/*
 * Copyright 2004-2024 the Pacemaker project contributors
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
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>
#include <crm/common/iso8601.h>
#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>
#include <crm/pengine/rules.h>
#include <pacemaker-internal.h>
#include "libpacemaker_private.h"

static bool
evaluate_lifetime(xmlNode *lifetime, pcmk_scheduler_t *scheduler)
{
    bool result = FALSE;
    crm_time_t *next_change = crm_time_new_undefined();

    result = pe_evaluate_rules(lifetime, NULL, scheduler->now, next_change);
    if (crm_time_is_defined(next_change)) {
        time_t recheck = (time_t) crm_time_get_seconds_since_epoch(next_change);

        pe__update_recheck_time(recheck, scheduler, "constraint lifetime");
    }
    crm_time_free(next_change);
    return result;
}

/*!
 * \internal
 * \brief Unpack constraints from XML
 *
 * Given scheduler data, unpack all constraints from its input XML into
 * data structures.
 *
 * \param[in,out] scheduler  Scheduler data
 */
void
pcmk__unpack_constraints(pcmk_scheduler_t *scheduler)
{
    xmlNode *xml_constraints = pcmk_find_cib_element(scheduler->input,
                                                     PCMK_XE_CONSTRAINTS);

    for (xmlNode *xml_obj = pcmk__xe_first_child(xml_constraints, NULL, NULL,
                                                 NULL);
         xml_obj != NULL; xml_obj = pcmk__xe_next(xml_obj)) {

        xmlNode *lifetime = NULL;
        const char *id = crm_element_value(xml_obj, PCMK_XA_ID);
        const char *tag = (const char *) xml_obj->name;

        if (id == NULL) {
            pcmk__config_err("Ignoring <%s> constraint without "
                             PCMK_XA_ID, tag);
            continue;
        }

        crm_trace("Unpacking %s constraint '%s'", tag, id);

        lifetime = pcmk__xe_first_child(xml_obj, PCMK__XE_LIFETIME, NULL, NULL);
        if (lifetime != NULL) {
            pcmk__config_warn("Support for '" PCMK__XE_LIFETIME "' element "
                              "(in %s) is deprecated (the rules it contains "
                              "should instead be direct descendants of the "
                              "constraint object)", id);
        }

        if ((lifetime != NULL) && !evaluate_lifetime(lifetime, scheduler)) {
            crm_info("Constraint %s %s is not active", tag, id);

        } else if (pcmk__str_eq(PCMK_XE_RSC_ORDER, tag, pcmk__str_none)) {
            pcmk__unpack_ordering(xml_obj, scheduler);

        } else if (pcmk__str_eq(PCMK_XE_RSC_COLOCATION, tag, pcmk__str_none)) {
            pcmk__unpack_colocation(xml_obj, scheduler);

        } else if (pcmk__str_eq(PCMK_XE_RSC_LOCATION, tag, pcmk__str_none)) {
            pcmk__unpack_location(xml_obj, scheduler);

        } else if (pcmk__str_eq(PCMK_XE_RSC_TICKET, tag, pcmk__str_none)) {
            pcmk__unpack_rsc_ticket(xml_obj, scheduler);

        } else {
            pcmk__config_err("Unsupported constraint type: %s", tag);
        }
    }
}

pcmk_resource_t *
pcmk__find_constraint_resource(GList *rsc_list, const char *id)
{
    if (id == NULL) {
        return NULL;
    }
    for (GList *iter = rsc_list; iter != NULL; iter = iter->next) {
        pcmk_resource_t *parent = iter->data;
        pcmk_resource_t *match = parent->fns->find_rsc(parent, id, NULL,
                                                       pcmk_rsc_match_history);

        if (match != NULL) {
            if (!pcmk__str_eq(match->id, id, pcmk__str_none)) {
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

/*!
 * \internal
 * \brief Check whether an ID references a resource tag
 *
 * \param[in]  scheduler  Scheduler data
 * \param[in]  id         Tag ID to search for
 * \param[out] tag        Where to store tag, if found
 *
 * \return true if ID refers to a tagged resource or resource set template,
 *         otherwise false
 */
static bool
find_constraint_tag(const pcmk_scheduler_t *scheduler, const char *id,
                    pcmk_tag_t **tag)
{
    *tag = NULL;

    // Check whether id refers to a resource set template
    if (g_hash_table_lookup_extended(scheduler->template_rsc_sets, id,
                                     NULL, (gpointer *) tag)) {
        if (*tag == NULL) {
            crm_notice("No resource is derived from template '%s'", id);
            return false;
        }
        return true;
    }

    // If not, check whether id refers to a tag
    if (g_hash_table_lookup_extended(scheduler->tags, id,
                                     NULL, (gpointer *) tag)) {
        if (*tag == NULL) {
            crm_notice("No resource is tagged with '%s'", id);
            return false;
        }
        return true;
    }

    pcmk__config_warn("No resource, template, or tag named '%s'", id);
    return false;
}

/*!
 * \brief
 * \internal Check whether an ID refers to a valid resource or tag
 *
 * \param[in]  scheduler  Scheduler data
 * \param[in]  id         ID to search for
 * \param[out] rsc        Where to store resource, if found
 *                        (or NULL to skip searching resources)
 * \param[out] tag        Where to store tag, if found
 *                        (or NULL to skip searching tags)
 *
 * \return true if id refers to a resource (possibly indirectly via a tag)
 */
bool
pcmk__valid_resource_or_tag(const pcmk_scheduler_t *scheduler, const char *id,
                            pcmk_resource_t **rsc, pcmk_tag_t **tag)
{
    if (rsc != NULL) {
        *rsc = pcmk__find_constraint_resource(scheduler->resources, id);
        if (*rsc != NULL) {
            return true;
        }
    }

    if ((tag != NULL) && find_constraint_tag(scheduler, id, tag)) {
        return true;
    }

    return false;
}

/*!
 * \internal
 * \brief Replace any resource tags with equivalent \C PCMK_XE_RESOURCE_REF
 *        entries
 *
 * If a given constraint has resource sets, check each set for
 * \c PCMK_XE_RESOURCE_REF entries that list tags rather than resource IDs, and
 * replace any found with \c PCMK_XE_RESOURCE_REF entries for the corresponding
 * resource IDs.
 *
 * \param[in,out] xml_obj    Constraint XML
 * \param[in]     scheduler  Scheduler data
 *
 * \return Equivalent XML with resource tags replaced (or NULL if none)
 * \note It is the caller's responsibility to free the result with
 *       \c pcmk__xml_free().
 */
xmlNode *
pcmk__expand_tags_in_sets(xmlNode *xml_obj, const pcmk_scheduler_t *scheduler)
{
    xmlNode *new_xml = NULL;
    bool any_refs = false;

    // Short-circuit if there are no sets
    if (pcmk__xe_first_child(xml_obj, PCMK_XE_RESOURCE_SET, NULL,
                             NULL) == NULL) {
        return NULL;
    }

    new_xml = pcmk__xml_copy(NULL, xml_obj);

    for (xmlNode *set = pcmk__xe_first_child(new_xml, PCMK_XE_RESOURCE_SET,
                                             NULL, NULL);
         set != NULL; set = pcmk__xe_next_same(set)) {

        GList *tag_refs = NULL;
        GList *iter = NULL;

        for (xmlNode *xml_rsc = pcmk__xe_first_child(set, PCMK_XE_RESOURCE_REF,
                                                     NULL, NULL);
             xml_rsc != NULL; xml_rsc = pcmk__xe_next_same(xml_rsc)) {

            pcmk_resource_t *rsc = NULL;
            pcmk_tag_t *tag = NULL;

            if (!pcmk__valid_resource_or_tag(scheduler, pcmk__xe_id(xml_rsc),
                                             &rsc, &tag)) {
                pcmk__config_err("Ignoring resource sets for constraint '%s' "
                                 "because '%s' is not a valid resource or tag",
                                 pcmk__xe_id(xml_obj), pcmk__xe_id(xml_rsc));
                pcmk__xml_free(new_xml);
                return NULL;

            } else if (rsc) {
                continue;

            } else if (tag) {
                /* PCMK_XE_RESOURCE_REF under PCMK_XE_RESOURCE_SET references
                 * template or tag
                 */
                xmlNode *last_ref = xml_rsc;

                /* For example, given the original XML:
                 *
                 *   <resource_set id="tag1-colocation-0" sequential="true">
                 *     <resource_ref id="rsc1"/>
                 *     <resource_ref id="tag1"/>
                 *     <resource_ref id="rsc4"/>
                 *   </resource_set>
                 *
                 * If rsc2 and rsc3 are tagged with tag1, we add them after it:
                 *
                 *   <resource_set id="tag1-colocation-0" sequential="true">
                 *     <resource_ref id="rsc1"/>
                 *     <resource_ref id="tag1"/>
                 *     <resource_ref id="rsc2"/>
                 *     <resource_ref id="rsc3"/>
                 *     <resource_ref id="rsc4"/>
                 *   </resource_set>
                 */

                for (iter = tag->refs; iter != NULL; iter = iter->next) {
                    const char *obj_ref = iter->data;
                    xmlNode *new_rsc_ref = NULL;

                    new_rsc_ref = xmlNewDocRawNode(set->doc, NULL,
                                                   (pcmkXmlStr)
                                                   PCMK_XE_RESOURCE_REF,
                                                   NULL);
                    crm_xml_add(new_rsc_ref, PCMK_XA_ID, obj_ref);
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
        for (iter = tag_refs; iter != NULL; iter = iter->next) {
            xmlNode *tag_ref = iter->data;

            pcmk__xml_free(tag_ref);
        }
        g_list_free(tag_refs);
    }

    if (!any_refs) {
        pcmk__xml_free(new_xml);
        new_xml = NULL;
    }
    return new_xml;
}

/*!
 * \internal
 * \brief Convert a tag into a resource set of tagged resources
 *
 * \param[in,out] xml_obj      Constraint XML
 * \param[out]    rsc_set      Where to store resource set XML
 * \param[in]     attr         Name of XML attribute with resource or tag ID
 * \param[in]     convert_rsc  If true, convert to set even if \p attr
 *                             references a resource
 * \param[in]     scheduler    Scheduler data
 */
bool
pcmk__tag_to_set(xmlNode *xml_obj, xmlNode **rsc_set, const char *attr,
                 bool convert_rsc, const pcmk_scheduler_t *scheduler)
{
    const char *cons_id = NULL;
    const char *id = NULL;

    pcmk_resource_t *rsc = NULL;
    pcmk_tag_t *tag = NULL;

    *rsc_set = NULL;

    CRM_CHECK((xml_obj != NULL) && (attr != NULL), return false);

    cons_id = pcmk__xe_id(xml_obj);
    if (cons_id == NULL) {
        pcmk__config_err("Ignoring <%s> constraint without " PCMK_XA_ID,
                         xml_obj->name);
        return false;
    }

    id = crm_element_value(xml_obj, attr);
    if (id == NULL) {
        return true;
    }

    if (!pcmk__valid_resource_or_tag(scheduler, id, &rsc, &tag)) {
        pcmk__config_err("Ignoring constraint '%s' because '%s' is not a "
                         "valid resource or tag", cons_id, id);
        return false;

    } else if (tag) {
        /* The "attr" attribute (for a resource in a constraint) specifies a
         * template or tag. Add the corresponding PCMK_XE_RESOURCE_SET
         * containing the resources derived from or tagged with it.
         */
        *rsc_set = pcmk__xe_create(xml_obj, PCMK_XE_RESOURCE_SET);
        crm_xml_add(*rsc_set, PCMK_XA_ID, id);

        for (GList *iter = tag->refs; iter != NULL; iter = iter->next) {
            const char *obj_ref = iter->data;
            xmlNode *rsc_ref = NULL;

            rsc_ref = pcmk__xe_create(*rsc_set, PCMK_XE_RESOURCE_REF);
            crm_xml_add(rsc_ref, PCMK_XA_ID, obj_ref);
        }

        // Set PCMK_XA_SEQUENTIAL=PCMK_VALUE_FALSE for the PCMK_XE_RESOURCE_SET
        pcmk__xe_set_bool_attr(*rsc_set, PCMK_XA_SEQUENTIAL, false);

    } else if ((rsc != NULL) && convert_rsc) {
        /* Even if a regular resource is referenced by "attr", convert it into a
         * PCMK_XE_RESOURCE_SET, because the other resource reference in the
         * constraint could be a template or tag.
         */
        xmlNode *rsc_ref = NULL;

        *rsc_set = pcmk__xe_create(xml_obj, PCMK_XE_RESOURCE_SET);
        crm_xml_add(*rsc_set, PCMK_XA_ID, id);

        rsc_ref = pcmk__xe_create(*rsc_set, PCMK_XE_RESOURCE_REF);
        crm_xml_add(rsc_ref, PCMK_XA_ID, id);

    } else {
        return true;
    }

    /* Remove the "attr" attribute referencing the template/tag */
    if (*rsc_set != NULL) {
        pcmk__xe_remove_attr(xml_obj, attr);
    }

    return true;
}

/*!
 * \internal
 * \brief Create constraints inherent to resource types
 *
 * \param[in,out] scheduler  Scheduler data
 */
void
pcmk__create_internal_constraints(pcmk_scheduler_t *scheduler)
{
    crm_trace("Create internal constraints");
    for (GList *iter = scheduler->resources; iter != NULL; iter = iter->next) {
        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

        rsc->cmds->internal_constraints(rsc);
    }
}

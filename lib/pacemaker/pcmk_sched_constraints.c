/*
 * Copyright 2004-2023 the Pacemaker project contributors
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

/*!
 * \internal
 * \brief Unpack constraints from XML
 *
 * Given a cluster working set, unpack all constraints from its input XML into
 * data structures.
 *
 * \param[in,out] data_set  Cluster working set
 */
void
pcmk__unpack_constraints(pe_working_set_t *data_set)
{
    xmlNode *xml_constraints = pcmk_find_cib_element(data_set->input,
                                                     XML_CIB_TAG_CONSTRAINTS);

    for (xmlNode *xml_obj = pcmk__xe_first_child(xml_constraints);
         xml_obj != NULL; xml_obj = pcmk__xe_next(xml_obj)) {

        xmlNode *lifetime = NULL;
        const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
        const char *tag = crm_element_name(xml_obj);

        if (id == NULL) {
            pcmk__config_err("Ignoring <%s> constraint without "
                             XML_ATTR_ID, tag);
            continue;
        }

        crm_trace("Unpacking %s constraint '%s'", tag, id);

        lifetime = first_named_child(xml_obj, "lifetime");
        if (lifetime != NULL) {
            pcmk__config_warn("Support for 'lifetime' attribute (in %s) is "
                              "deprecated (the rules it contains should "
                              "instead be direct descendants of the "
                              "constraint object)", id);
        }

        if ((lifetime != NULL) && !evaluate_lifetime(lifetime, data_set)) {
            crm_info("Constraint %s %s is not active", tag, id);

        } else if (pcmk__str_eq(XML_CONS_TAG_RSC_ORDER, tag, pcmk__str_casei)) {
            pcmk__unpack_ordering(xml_obj, data_set);

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

/*!
 * \internal
 * \brief Check whether an ID references a resource tag
 *
 * \param[in]  data_set  Cluster working set
 * \param[in]  id        Tag ID to search for
 * \param[out] tag       Where to store tag, if found
 *
 * \return true if ID refers to a tagged resource or resource set template,
 *         otherwise false
 */
static bool
find_constraint_tag(const pe_working_set_t *data_set, const char *id,
                    pe_tag_t **tag)
{
    *tag = NULL;

    // Check whether id refers to a resource set template
    if (g_hash_table_lookup_extended(data_set->template_rsc_sets, id,
                                     NULL, (gpointer *) tag)) {
        if (*tag == NULL) {
            crm_warn("No resource is derived from template '%s'", id);
            return false;
        }
        return true;
    }

    // If not, check whether id refers to a tag
    if (g_hash_table_lookup_extended(data_set->tags, id,
                                     NULL, (gpointer *) tag)) {
        if (*tag == NULL) {
            crm_warn("No resource is tagged with '%s'", id);
            return false;
        }
        return true;
    }

    crm_warn("No template or tag named '%s'", id);
    return false;
}

/*!
 * \brief
 * \internal Check whether an ID refers to a valid resource or tag
 *
 * \param[in]  data_set Cluster working set
 * \param[in]  id       ID to search for
 * \param[out] rsc      Where to store resource, if found (or NULL to skip
 *                      searching resources)
 * \param[out] tag      Where to store tag, if found (or NULL to skip searching
 *                      tags)
 *
 * \return true if id refers to a resource (possibly indirectly via a tag)
 */
bool
pcmk__valid_resource_or_tag(const pe_working_set_t *data_set, const char *id,
                            pe_resource_t **rsc, pe_tag_t **tag)
{
    if (rsc != NULL) {
        *rsc = pcmk__find_constraint_resource(data_set->resources, id);
        if (*rsc != NULL) {
            return true;
        }
    }

    if ((tag != NULL) && find_constraint_tag(data_set, id, tag)) {
        return true;
    }

    return false;
}

/*!
 * \internal
 * \brief Replace any resource tags with equivalent resource_ref entries
 *
 * If a given constraint has resource sets, check each set for resource_ref
 * entries that list tags rather than resource IDs, and replace any found with
 * resource_ref entries for the corresponding resource IDs.
 *
 * \param[in,out] xml_obj   Constraint XML
 * \param[in]     data_set  Cluster working set
 *
 * \return Equivalent XML with resource tags replaced (or NULL if none)
 * \note It is the caller's responsibility to free the result with free_xml().
 */
xmlNode *
pcmk__expand_tags_in_sets(xmlNode *xml_obj, const pe_working_set_t *data_set)
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

/*!
 * \internal
 * \brief Convert a tag into a resource set of tagged resources
 *
 * \param[in,out] xml_obj      Constraint XML
 * \param[out]    rsc_set      Where to store resource set XML created based on tag
 * \param[in]     attr         Name of XML attribute containing resource or tag ID
 * \param[in]     convert_rsc  Convert to set even if \p attr references a resource
 * \param[in]     data_set     Cluster working set
 */
bool
pcmk__tag_to_set(xmlNode *xml_obj, xmlNode **rsc_set, const char *attr,
                 bool convert_rsc, const pe_working_set_t *data_set)
{
    const char *cons_id = NULL;
    const char *id = NULL;

    pe_resource_t *rsc = NULL;
    pe_tag_t *tag = NULL;

    *rsc_set = NULL;

    CRM_CHECK((xml_obj != NULL) && (attr != NULL), return false);

    cons_id = ID(xml_obj);
    if (cons_id == NULL) {
        pcmk__config_err("Ignoring <%s> constraint without " XML_ATTR_ID,
                         crm_element_name(xml_obj));
        return false;
    }

    id = crm_element_value(xml_obj, attr);
    if (id == NULL) {
        return true;
    }

    if (!pcmk__valid_resource_or_tag(data_set, id, &rsc, &tag)) {
        pcmk__config_err("Ignoring constraint '%s' because '%s' is not a "
                         "valid resource or tag", cons_id, id);
        return false;

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
        pcmk__xe_set_bool_attr(*rsc_set, "sequential", false);

    } else if ((rsc != NULL) && convert_rsc) {
        /* Even a regular resource is referenced by "attr", convert it into a resource_set.
           Because the other side of the constraint could be a template/tag reference. */
        xmlNode *rsc_ref = NULL;

        *rsc_set = create_xml_node(xml_obj, XML_CONS_TAG_RSC_SET);
        crm_xml_add(*rsc_set, XML_ATTR_ID, id);

        rsc_ref = create_xml_node(*rsc_set, XML_TAG_RESOURCE_REF);
        crm_xml_add(rsc_ref, XML_ATTR_ID, id);

    } else {
        return true;
    }

    /* Remove the "attr" attribute referencing the template/tag */
    if (*rsc_set != NULL) {
        xml_remove_prop(xml_obj, attr);
    }

    return true;
}

/*!
 * \internal
 * \brief Create constraints inherent to resource types
 *
 * \param[in,out] data_set  Cluster working set
 */
void
pcmk__create_internal_constraints(pe_working_set_t *data_set)
{
    crm_trace("Create internal constraints");
    for (GList *iter = data_set->resources; iter != NULL; iter = iter->next) {
        pe_resource_t *rsc = (pe_resource_t *) iter->data;

        rsc->cmds->internal_constraints(rsc);
    }
}

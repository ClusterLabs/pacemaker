/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>
#include <unpack.h>
#include <crm/msg_xml.h>

#define VARIANT_GROUP 1
#include "./variant.h"

gboolean
group_unpack(resource_t * rsc, pe_working_set_t * data_set)
{
    xmlNode *xml_obj = rsc->xml;
    xmlNode *xml_native_rsc = NULL;
    group_variant_data_t *group_data = NULL;
    const char *group_ordered = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_ORDERED);
    const char *group_colocated = g_hash_table_lookup(rsc->meta, "collocated");
    const char *clone_id = NULL;

    pe_rsc_trace(rsc, "Processing resource %s...", rsc->id);

    group_data = calloc(1, sizeof(group_variant_data_t));
    group_data->num_children = 0;
    group_data->first_child = NULL;
    group_data->last_child = NULL;
    rsc->variant_opaque = group_data;

    group_data->ordered = TRUE;
    group_data->colocated = TRUE;

    if (group_ordered != NULL) {
        crm_str_to_boolean(group_ordered, &(group_data->ordered));
    }
    if (group_colocated != NULL) {
        crm_str_to_boolean(group_colocated, &(group_data->colocated));
    }

    clone_id = crm_element_value(rsc->xml, XML_RSC_ATTR_INCARNATION);

    for (xml_native_rsc = __xml_first_child(xml_obj); xml_native_rsc != NULL;
         xml_native_rsc = __xml_next(xml_native_rsc)) {
        if (crm_str_eq((const char *)xml_native_rsc->name, XML_CIB_TAG_RESOURCE, TRUE)) {
            resource_t *new_rsc = NULL;

            crm_xml_add(xml_native_rsc, XML_RSC_ATTR_INCARNATION, clone_id);
            if (common_unpack(xml_native_rsc, &new_rsc, rsc, data_set) == FALSE) {
                pe_err("Failed unpacking resource %s", crm_element_value(xml_obj, XML_ATTR_ID));
                if (new_rsc != NULL && new_rsc->fns != NULL) {
                    new_rsc->fns->free(new_rsc);
                }
            }

            group_data->num_children++;
            rsc->children = g_list_append(rsc->children, new_rsc);

            if (group_data->first_child == NULL) {
                group_data->first_child = new_rsc;
            }
            group_data->last_child = new_rsc;
            print_resource(LOG_DEBUG_3, "Added ", new_rsc, FALSE);
        }
    }

    if (group_data->num_children == 0) {
#if 0
        /* Bug #1287 */
        crm_config_err("Group %s did not have any children", rsc->id);
        return FALSE;
#else
        crm_config_warn("Group %s did not have any children", rsc->id);
        return TRUE;
#endif
    }

    pe_rsc_trace(rsc, "Added %d children to resource %s...", group_data->num_children, rsc->id);

    return TRUE;
}

gboolean
group_active(resource_t * rsc, gboolean all)
{
    gboolean c_all = TRUE;
    gboolean c_any = FALSE;
    GListPtr gIter = rsc->children;

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        if (child_rsc->fns->active(child_rsc, all)) {
            c_any = TRUE;
        } else {
            c_all = FALSE;
        }
    }

    if (c_any == FALSE) {
        return FALSE;
    } else if (all && c_all == FALSE) {
        return FALSE;
    }
    return TRUE;
}

static void
group_print_xml(resource_t * rsc, const char *pre_text, long options, void *print_data)
{
    GListPtr gIter = rsc->children;
    char *child_text = crm_concat(pre_text, "    ", ' ');

    status_print("%s<group id=\"%s\" ", pre_text, rsc->id);
    status_print("number_resources=\"%d\" ", g_list_length(rsc->children));
    status_print(">\n");

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        child_rsc->fns->print(child_rsc, child_text, options, print_data);
    }

    status_print("%s</group>\n", pre_text);
    free(child_text);
}

void
group_print(resource_t * rsc, const char *pre_text, long options, void *print_data)
{
    char *child_text = NULL;
    GListPtr gIter = rsc->children;

    if (pre_text == NULL) {
        pre_text = " ";
    }

    if (options & pe_print_xml) {
        group_print_xml(rsc, pre_text, options, print_data);
        return;
    }

    child_text = crm_concat(pre_text, "   ", ' ');

    status_print("%sResource Group: %s", pre_text ? pre_text : "", rsc->id);

    if (options & pe_print_html) {
        status_print("\n<ul>\n");

    } else if ((options & pe_print_log) == 0) {
        status_print("\n");
    }

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        if (options & pe_print_html) {
            status_print("<li>\n");
        }
        child_rsc->fns->print(child_rsc, child_text, options, print_data);
        if (options & pe_print_html) {
            status_print("</li>\n");
        }
    }

    if (options & pe_print_html) {
        status_print("</ul>\n");
    }
    free(child_text);
}

void
group_free(resource_t * rsc)
{
    GListPtr gIter = rsc->children;

    CRM_CHECK(rsc != NULL, return);

    pe_rsc_trace(rsc, "Freeing %s", rsc->id);

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        pe_rsc_trace(child_rsc, "Freeing child %s", child_rsc->id);
        child_rsc->fns->free(child_rsc);
    }

    pe_rsc_trace(rsc, "Freeing child list");
    g_list_free(rsc->children);

    common_free(rsc);
}

enum rsc_role_e
group_resource_state(const resource_t * rsc, gboolean current)
{
    enum rsc_role_e group_role = RSC_ROLE_UNKNOWN;
    GListPtr gIter = rsc->children;

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;
        enum rsc_role_e role = child_rsc->fns->state(child_rsc, current);

        if (role > group_role) {
            group_role = role;
        }
    }

    pe_rsc_trace(rsc, "%s role: %s", rsc->id, role2text(group_role));
    return group_role;
}

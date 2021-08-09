/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>
#include <crm/msg_xml.h>
#include <crm/common/output.h>
#include <crm/common/strings_internal.h>
#include <crm/common/xml_internal.h>
#include <pe_status_private.h>

#define VARIANT_GROUP 1
#include "./variant.h"

static int
inactive_resources(pe_resource_t *rsc)
{
    int retval = 0;

    for (GList *gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        if (!child_rsc->fns->active(child_rsc, TRUE)) {
            retval++;
        }
    }

    return retval;
}

static void
group_header(pcmk__output_t *out, int *rc, pe_resource_t *rsc, int n_inactive, bool show_inactive)
{
    char *attrs = NULL;
    size_t len = 0;

    if (n_inactive > 0 && !show_inactive) {
        char *word = crm_strdup_printf("%d member%s inactive", n_inactive, pcmk__plural_s(n_inactive));
        pcmk__add_separated_word(&attrs, &len, word, ", ");
        free(word);
    }

    if (!pcmk_is_set(rsc->flags, pe_rsc_managed)) {
        pcmk__add_separated_word(&attrs, &len, "unmanaged", ", ");
    }

    if (pe__resource_is_disabled(rsc)) {
        pcmk__add_separated_word(&attrs, &len, "disabled", ", ");
    }

    if (attrs) {
        PCMK__OUTPUT_LIST_HEADER(out, FALSE, *rc, "Resource Group: %s (%s)",
                                 rsc->id, attrs);
        free(attrs);
    } else {
        PCMK__OUTPUT_LIST_HEADER(out, FALSE, *rc, "Resource Group: %s", rsc->id);
    }
}

static bool
skip_child_rsc(pe_resource_t *rsc, pe_resource_t *child, gboolean parent_passes,
               GList *only_rsc, unsigned int show_opts)
{
    bool star_list = pcmk__list_of_1(only_rsc) &&
                     pcmk__str_eq("*", g_list_first(only_rsc)->data, pcmk__str_none);
    bool child_filtered = child->fns->is_filtered(child, only_rsc, FALSE);
    bool child_active = child->fns->active(child, FALSE);
    bool show_inactive = pcmk_is_set(show_opts, pcmk_show_inactive_rscs);

    /* If the resource is in only_rsc by name (so, ignoring "*") then allow
     * it regardless of if it's active or not.
     */
    if (!star_list && !child_filtered) {
        return false;

    } else if (!child_filtered && (child_active || show_inactive)) {
        return false;

    } else if (parent_passes && (child_active || show_inactive)) {
        return false;

    }

    return true;
}

gboolean
group_unpack(pe_resource_t * rsc, pe_working_set_t * data_set)
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

    // We don't actually need the null checks but it speeds up the common case
    if ((group_ordered == NULL)
        || (crm_str_to_boolean(group_ordered, &(group_data->ordered)) < 0)) {
        group_data->ordered = TRUE;
    }
    if ((group_colocated == NULL)
        || (crm_str_to_boolean(group_colocated, &(group_data->colocated)) < 0)) {
        group_data->colocated = TRUE;
    }

    clone_id = crm_element_value(rsc->xml, XML_RSC_ATTR_INCARNATION);

    for (xml_native_rsc = pcmk__xe_first_child(xml_obj); xml_native_rsc != NULL;
         xml_native_rsc = pcmk__xe_next(xml_native_rsc)) {

        if (pcmk__str_eq((const char *)xml_native_rsc->name,
                         XML_CIB_TAG_RESOURCE, pcmk__str_none)) {
            pe_resource_t *new_rsc = NULL;

            crm_xml_add(xml_native_rsc, XML_RSC_ATTR_INCARNATION, clone_id);
            if (common_unpack(xml_native_rsc, &new_rsc, rsc, data_set) == FALSE) {
                pe_err("Failed unpacking resource %s", crm_element_value(xml_obj, XML_ATTR_ID));
                if (new_rsc != NULL && new_rsc->fns != NULL) {
                    new_rsc->fns->free(new_rsc);
                }
                continue;
            }

            group_data->num_children++;
            rsc->children = g_list_append(rsc->children, new_rsc);

            if (group_data->first_child == NULL) {
                group_data->first_child = new_rsc;
            }
            group_data->last_child = new_rsc;
            pe_rsc_trace(rsc, "Added %s member %s", rsc->id, new_rsc->id);
        }
    }

    if (group_data->num_children == 0) {
        pcmk__config_warn("Group %s does not have any children", rsc->id);
        return TRUE; // Allow empty groups, children can be added later
    }

    pe_rsc_trace(rsc, "Added %d children to resource %s...", group_data->num_children, rsc->id);

    return TRUE;
}

gboolean
group_active(pe_resource_t * rsc, gboolean all)
{
    gboolean c_all = TRUE;
    gboolean c_any = FALSE;
    GList *gIter = rsc->children;

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

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
group_print_xml(pe_resource_t * rsc, const char *pre_text, long options, void *print_data)
{
    GList *gIter = rsc->children;
    char *child_text = crm_strdup_printf("%s     ", pre_text);

    status_print("%s<group id=\"%s\" ", pre_text, rsc->id);
    status_print("number_resources=\"%d\" ", g_list_length(rsc->children));
    status_print(">\n");

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->fns->print(child_rsc, child_text, options, print_data);
    }

    status_print("%s</group>\n", pre_text);
    free(child_text);
}

void
group_print(pe_resource_t * rsc, const char *pre_text, long options, void *print_data)
{
    char *child_text = NULL;
    GList *gIter = rsc->children;

    if (pre_text == NULL) {
        pre_text = " ";
    }

    if (options & pe_print_xml) {
        group_print_xml(rsc, pre_text, options, print_data);
        return;
    }

    child_text = crm_strdup_printf("%s    ", pre_text);

    status_print("%sResource Group: %s", pre_text ? pre_text : "", rsc->id);

    if (options & pe_print_html) {
        status_print("\n<ul>\n");

    } else if ((options & pe_print_log) == 0) {
        status_print("\n");
    }

    if (options & pe_print_brief) {
        print_rscs_brief(rsc->children, child_text, options, print_data, TRUE);

    } else {
        for (; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

            if (options & pe_print_html) {
                status_print("<li>\n");
            }
            child_rsc->fns->print(child_rsc, child_text, options, print_data);
            if (options & pe_print_html) {
                status_print("</li>\n");
            }
        }
    }

    if (options & pe_print_html) {
        status_print("</ul>\n");
    }
    free(child_text);
}

PCMK__OUTPUT_ARGS("group", "unsigned int", "pe_resource_t *", "GList *", "GList *")
int
pe__group_xml(pcmk__output_t *out, va_list args)
{
    unsigned int show_opts = va_arg(args, unsigned int);
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    GList *gIter = rsc->children;
    char *count = pcmk__itoa(g_list_length(gIter));

    int rc = pcmk_rc_no_output;

    gboolean parent_passes = pcmk__str_in_list(rsc_printable_id(rsc), only_rsc, pcmk__str_star_matches) ||
                             (strstr(rsc->id, ":") != NULL && pcmk__str_in_list(rsc->id, only_rsc, pcmk__str_star_matches));

    if (rsc->fns->is_filtered(rsc, only_rsc, TRUE)) {
        free(count);
        return rc;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        if (skip_child_rsc(rsc, child_rsc, parent_passes, only_rsc, show_opts)) {
            continue;
        }

        if (rc == pcmk_rc_no_output) {
            rc = pe__name_and_nvpairs_xml(out, true, "group", 4
                                          , "id", rsc->id
                                          , "number_resources", count
                                          , "managed", pe__rsc_bool_str(rsc, pe_rsc_managed)
                                          , "disabled", pcmk__btoa(pe__resource_is_disabled(rsc)));
            free(count);
            CRM_ASSERT(rc == pcmk_rc_ok);
        }

        out->message(out, crm_map_element_name(child_rsc->xml), show_opts, child_rsc,
					 only_node, only_rsc);
    }

    if (rc == pcmk_rc_ok) {
        pcmk__output_xml_pop_parent(out);
    }

    return rc;
}

PCMK__OUTPUT_ARGS("group", "unsigned int", "pe_resource_t *", "GList *", "GList *")
int
pe__group_default(pcmk__output_t *out, va_list args)
{
    unsigned int show_opts = va_arg(args, unsigned int);
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    int rc = pcmk_rc_no_output;

    gboolean parent_passes = pcmk__str_in_list(rsc_printable_id(rsc), only_rsc, pcmk__str_star_matches) ||
                             (strstr(rsc->id, ":") != NULL && pcmk__str_in_list(rsc->id, only_rsc, pcmk__str_star_matches));

    gboolean active = rsc->fns->active(rsc, TRUE);
    gboolean partially_active = rsc->fns->active(rsc, FALSE);

    if (rsc->fns->is_filtered(rsc, only_rsc, TRUE)) {
        return rc;
    }

    if (pcmk_is_set(show_opts, pcmk_show_brief)) {
        GList *rscs = pe__filter_rsc_list(rsc->children, only_rsc);

        if (rscs != NULL) {
            group_header(out, &rc, rsc, !active && partially_active ? inactive_resources(rsc) : 0,
                         pcmk_is_set(show_opts, pcmk_show_inactive_rscs));
            pe__rscs_brief_output(out, rscs, show_opts | pcmk_show_inactive_rscs);

            rc = pcmk_rc_ok;
            g_list_free(rscs);
        }

    } else {
        for (GList *gIter = rsc->children; gIter; gIter = gIter->next) {
            pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

            if (skip_child_rsc(rsc, child_rsc, parent_passes, only_rsc, show_opts)) {
                continue;
            }

            group_header(out, &rc, rsc, !active && partially_active ? inactive_resources(rsc) : 0,
                         pcmk_is_set(show_opts, pcmk_show_inactive_rscs));
            out->message(out, crm_map_element_name(child_rsc->xml), show_opts,
                         child_rsc, only_node, only_rsc);
        }
    }

	PCMK__OUTPUT_LIST_FOOTER(out, rc);

    return rc;
}

void
group_free(pe_resource_t * rsc)
{
    CRM_CHECK(rsc != NULL, return);

    pe_rsc_trace(rsc, "Freeing %s", rsc->id);

    for (GList *gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        CRM_ASSERT(child_rsc);
        pe_rsc_trace(child_rsc, "Freeing child %s", child_rsc->id);
        child_rsc->fns->free(child_rsc);
    }

    pe_rsc_trace(rsc, "Freeing child list");
    g_list_free(rsc->children);

    common_free(rsc);
}

enum rsc_role_e
group_resource_state(const pe_resource_t * rsc, gboolean current)
{
    enum rsc_role_e group_role = RSC_ROLE_UNKNOWN;
    GList *gIter = rsc->children;

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;
        enum rsc_role_e role = child_rsc->fns->state(child_rsc, current);

        if (role > group_role) {
            group_role = role;
        }
    }

    pe_rsc_trace(rsc, "%s role: %s", rsc->id, role2text(group_role));
    return group_role;
}

gboolean
pe__group_is_filtered(pe_resource_t *rsc, GList *only_rsc, gboolean check_parent)
{
    gboolean passes = FALSE;

    if (check_parent && pcmk__str_in_list(rsc_printable_id(uber_parent(rsc)), only_rsc, pcmk__str_star_matches)) {
        passes = TRUE;
    } else if (pcmk__str_in_list(rsc_printable_id(rsc), only_rsc, pcmk__str_star_matches)) {
        passes = TRUE;
    } else if (strstr(rsc->id, ":") != NULL && pcmk__str_in_list(rsc->id, only_rsc, pcmk__str_star_matches)) {
        passes = TRUE;
    } else {
        for (GList *gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

            if (!child_rsc->fns->is_filtered(child_rsc, only_rsc, FALSE)) {
                passes = TRUE;
                break;
            }
        }
    }

    return !passes;
}

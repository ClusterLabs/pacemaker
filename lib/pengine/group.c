/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdint.h>

#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>
#include <crm/common/xml.h>
#include <crm/common/output.h>
#include <crm/common/strings_internal.h>
#include <crm/common/xml_internal.h>
#include <pe_status_private.h>

typedef struct group_variant_data_s {
    pcmk_resource_t *last_child;    // Last group member
    uint32_t flags;                 // Group of enum pcmk__group_flags
} group_variant_data_t;

/*!
 * \internal
 * \brief Get a group's last member
 *
 * \param[in] group  Group resource to check
 *
 * \return Last member of \p group if any, otherwise NULL
 */
pcmk_resource_t *
pe__last_group_member(const pcmk_resource_t *group)
{
    if (group != NULL) {
        const group_variant_data_t *group_data = NULL;

        CRM_CHECK(pcmk__is_group(group), return NULL);
        group_data = group->private->variant_opaque;
        return group_data->last_child;
    }
    return NULL;
}

/*!
 * \internal
 * \brief Check whether a group flag is set
 *
 * \param[in] group  Group resource to check
 * \param[in] flags  Flag or flags to check
 *
 * \return true if all \p flags are set for \p group, otherwise false
 */
bool
pe__group_flag_is_set(const pcmk_resource_t *group, uint32_t flags)
{
    const group_variant_data_t *group_data = NULL;

    CRM_CHECK(pcmk__is_group(group), return false);
    group_data = group->private->variant_opaque;
    return pcmk_all_flags_set(group_data->flags, flags);
}

/*!
 * \internal
 * \brief Set a (deprecated) group flag
 *
 * \param[in,out] group   Group resource to check
 * \param[in]     option  Name of boolean configuration option
 * \param[in]     flag    Flag to set if \p option is true (which is default)
 * \param[in]     wo_bit  "Warn once" flag to use for deprecation warning
 */
static void
set_group_flag(pcmk_resource_t *group, const char *option, uint32_t flag,
               uint32_t wo_bit)
{
    const char *value_s = NULL;
    int value = 0;

    value_s = g_hash_table_lookup(group->meta, option);

    // We don't actually need the null check but it speeds up the common case
    if ((value_s == NULL) || (crm_str_to_boolean(value_s, &value) < 0)
        || (value != 0)) {
        group_variant_data_t *group_data = group->private->variant_opaque;

        group_data->flags |= flag;

    } else {
        pcmk__warn_once(wo_bit,
                        "Support for the '%s' group meta-attribute is "
                        "deprecated and will be removed in a future release "
                        "(use a resource set instead)", option);
    }
}

static int
inactive_resources(pcmk_resource_t *rsc)
{
    int retval = 0;

    for (GList *gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        pcmk_resource_t *child_rsc = (pcmk_resource_t *) gIter->data;

        if (!child_rsc->private->fns->active(child_rsc, TRUE)) {
            retval++;
        }
    }

    return retval;
}

static void
group_header(pcmk__output_t *out, int *rc, const pcmk_resource_t *rsc,
             int n_inactive, bool show_inactive, const char *desc)
{
    GString *attrs = NULL;

    if (n_inactive > 0 && !show_inactive) {
        attrs = g_string_sized_new(64);
        g_string_append_printf(attrs, "%d member%s inactive", n_inactive,
                               pcmk__plural_s(n_inactive));
    }

    if (pe__resource_is_disabled(rsc)) {
        pcmk__add_separated_word(&attrs, 64, "disabled", ", ");
    }

    if (pcmk_is_set(rsc->flags, pcmk_rsc_maintenance)) {
        pcmk__add_separated_word(&attrs, 64, "maintenance", ", ");

    } else if (!pcmk_is_set(rsc->flags, pcmk_rsc_managed)) {
        pcmk__add_separated_word(&attrs, 64, "unmanaged", ", ");
    }

    if (attrs != NULL) {
        PCMK__OUTPUT_LIST_HEADER(out, FALSE, *rc, "Resource Group: %s (%s)%s%s%s",
                                 rsc->id,
                                 (const char *) attrs->str, desc ? " (" : "",
                                 desc ? desc : "", desc ? ")" : "");
        g_string_free(attrs, TRUE);
    } else {
        PCMK__OUTPUT_LIST_HEADER(out, FALSE, *rc, "Resource Group: %s%s%s%s",
                                 rsc->id,
                                 desc ? " (" : "", desc ? desc : "",
                                 desc ? ")" : "");
    }
}

static bool
skip_child_rsc(pcmk_resource_t *rsc, pcmk_resource_t *child,
               gboolean parent_passes, GList *only_rsc, uint32_t show_opts)
{
    bool star_list = pcmk__list_of_1(only_rsc) &&
                     pcmk__str_eq("*", g_list_first(only_rsc)->data, pcmk__str_none);
    bool child_filtered = child->private->fns->is_filtered(child, only_rsc,
                                                           FALSE);
    bool child_active = child->private->fns->active(child, FALSE);
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
group_unpack(pcmk_resource_t *rsc, pcmk_scheduler_t *scheduler)
{
    xmlNode *xml_obj = rsc->private->xml;
    xmlNode *xml_native_rsc = NULL;
    group_variant_data_t *group_data = NULL;
    const char *clone_id = NULL;

    pcmk__rsc_trace(rsc, "Processing resource %s...", rsc->id);

    group_data = pcmk__assert_alloc(1, sizeof(group_variant_data_t));
    group_data->last_child = NULL;
    rsc->private->variant_opaque = group_data;

    // @COMPAT These are deprecated since 2.1.5
    set_group_flag(rsc, PCMK_META_ORDERED, pcmk__group_ordered,
                   pcmk__wo_group_order);
    set_group_flag(rsc, "collocated", pcmk__group_colocated,
                   pcmk__wo_group_coloc);

    clone_id = crm_element_value(rsc->private->xml, PCMK__META_CLONE);

    for (xml_native_rsc = pcmk__xe_first_child(xml_obj, NULL, NULL, NULL);
         xml_native_rsc != NULL;
         xml_native_rsc = pcmk__xe_next(xml_native_rsc)) {

        if (pcmk__xe_is(xml_native_rsc, PCMK_XE_PRIMITIVE)) {
            pcmk_resource_t *new_rsc = NULL;

            crm_xml_add(xml_native_rsc, PCMK__META_CLONE, clone_id);
            if (pe__unpack_resource(xml_native_rsc, &new_rsc, rsc,
                                    scheduler) != pcmk_rc_ok) {
                continue;
            }

            rsc->children = g_list_append(rsc->children, new_rsc);
            group_data->last_child = new_rsc;
            pcmk__rsc_trace(rsc, "Added %s member %s", rsc->id, new_rsc->id);
        }
    }

    if (rsc->children == NULL) {
        /* The schema does not allow empty groups, but if validation is
         * disabled, we allow them (members can be added later).
         *
         * @COMPAT At a major release bump, we should consider this a failure so
         *         that group methods can assume children is not NULL, and there
         *         are no strange effects from phantom groups due to their
         *         presence or meta-attributes.
         */
        pcmk__config_warn("Group %s will be ignored because it does not have "
                          "any members", rsc->id);
    }
    return TRUE;
}

gboolean
group_active(pcmk_resource_t *rsc, gboolean all)
{
    gboolean c_all = TRUE;
    gboolean c_any = FALSE;
    GList *gIter = rsc->children;

    for (; gIter != NULL; gIter = gIter->next) {
        pcmk_resource_t *child_rsc = (pcmk_resource_t *) gIter->data;

        if (child_rsc->private->fns->active(child_rsc, all)) {
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

PCMK__OUTPUT_ARGS("group", "uint32_t", "pcmk_resource_t *", "GList *",
                  "GList *")
int
pe__group_xml(pcmk__output_t *out, va_list args)
{
    uint32_t show_opts = va_arg(args, uint32_t);
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    const char *desc = NULL;
    GList *gIter = rsc->children;

    int rc = pcmk_rc_no_output;

    gboolean parent_passes = pcmk__str_in_list(rsc_printable_id(rsc), only_rsc, pcmk__str_star_matches) ||
                             (strstr(rsc->id, ":") != NULL && pcmk__str_in_list(rsc->id, only_rsc, pcmk__str_star_matches));

    desc = pe__resource_description(rsc, show_opts);

    if (rsc->private->fns->is_filtered(rsc, only_rsc, TRUE)) {
        return rc;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        pcmk_resource_t *child_rsc = (pcmk_resource_t *) gIter->data;

        if (skip_child_rsc(rsc, child_rsc, parent_passes, only_rsc, show_opts)) {
            continue;
        }

        if (rc == pcmk_rc_no_output) {
            char *count = pcmk__itoa(g_list_length(gIter));
            const char *maintenance = pcmk__flag_text(rsc->flags,
                                                      pcmk_rsc_maintenance);
            const char *managed = pcmk__flag_text(rsc->flags, pcmk_rsc_managed);
            const char *disabled = pcmk__btoa(pe__resource_is_disabled(rsc));

            rc = pe__name_and_nvpairs_xml(out, true, PCMK_XE_GROUP,
                                          PCMK_XA_ID, rsc->id,
                                          PCMK_XA_NUMBER_RESOURCES, count,
                                          PCMK_XA_MAINTENANCE, maintenance,
                                          PCMK_XA_MANAGED, managed,
                                          PCMK_XA_DISABLED, disabled,
                                          PCMK_XA_DESCRIPTION, desc,
                                          NULL);
            free(count);
            CRM_ASSERT(rc == pcmk_rc_ok);
        }

        out->message(out, (const char *) child_rsc->private->xml->name,
                     show_opts, child_rsc, only_node, only_rsc);
    }

    if (rc == pcmk_rc_ok) {
        pcmk__output_xml_pop_parent(out);
    }

    return rc;
}

PCMK__OUTPUT_ARGS("group", "uint32_t", "pcmk_resource_t *", "GList *",
                  "GList *")
int
pe__group_default(pcmk__output_t *out, va_list args)
{
    uint32_t show_opts = va_arg(args, uint32_t);
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    const char *desc = NULL;
    int rc = pcmk_rc_no_output;

    gboolean parent_passes = pcmk__str_in_list(rsc_printable_id(rsc), only_rsc, pcmk__str_star_matches) ||
                             (strstr(rsc->id, ":") != NULL && pcmk__str_in_list(rsc->id, only_rsc, pcmk__str_star_matches));

    gboolean active = rsc->private->fns->active(rsc, TRUE);
    gboolean partially_active = rsc->private->fns->active(rsc, FALSE);

    desc = pe__resource_description(rsc, show_opts);

    if (rsc->private->fns->is_filtered(rsc, only_rsc, TRUE)) {
        return rc;
    }

    if (pcmk_is_set(show_opts, pcmk_show_brief)) {
        GList *rscs = pe__filter_rsc_list(rsc->children, only_rsc);

        if (rscs != NULL) {
            group_header(out, &rc, rsc, !active && partially_active ? inactive_resources(rsc) : 0,
                         pcmk_is_set(show_opts, pcmk_show_inactive_rscs), desc);
            pe__rscs_brief_output(out, rscs, show_opts | pcmk_show_inactive_rscs);

            rc = pcmk_rc_ok;
            g_list_free(rscs);
        }

    } else {
        for (GList *gIter = rsc->children; gIter; gIter = gIter->next) {
            pcmk_resource_t *child_rsc = (pcmk_resource_t *) gIter->data;

            if (skip_child_rsc(rsc, child_rsc, parent_passes, only_rsc, show_opts)) {
                continue;
            }

            group_header(out, &rc, rsc, !active && partially_active ? inactive_resources(rsc) : 0,
                         pcmk_is_set(show_opts, pcmk_show_inactive_rscs), desc);
            out->message(out, (const char *) child_rsc->private->xml->name,
                         show_opts, child_rsc, only_node, only_rsc);
        }
    }

	PCMK__OUTPUT_LIST_FOOTER(out, rc);

    return rc;
}

void
group_free(pcmk_resource_t * rsc)
{
    CRM_CHECK(rsc != NULL, return);

    pcmk__rsc_trace(rsc, "Freeing %s", rsc->id);

    for (GList *gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        pcmk_resource_t *child_rsc = (pcmk_resource_t *) gIter->data;

        CRM_ASSERT(child_rsc);
        pcmk__rsc_trace(child_rsc, "Freeing child %s", child_rsc->id);
        child_rsc->private->fns->free(child_rsc);
    }

    pcmk__rsc_trace(rsc, "Freeing child list");
    g_list_free(rsc->children);

    common_free(rsc);
}

enum rsc_role_e
group_resource_state(const pcmk_resource_t * rsc, gboolean current)
{
    enum rsc_role_e group_role = pcmk_role_unknown;
    GList *gIter = rsc->children;

    for (; gIter != NULL; gIter = gIter->next) {
        pcmk_resource_t *child_rsc = (pcmk_resource_t *) gIter->data;
        enum rsc_role_e role = child_rsc->private->fns->state(child_rsc,
                                                              current);

        if (role > group_role) {
            group_role = role;
        }
    }

    pcmk__rsc_trace(rsc, "%s role: %s", rsc->id, pcmk_role_text(group_role));
    return group_role;
}

gboolean
pe__group_is_filtered(const pcmk_resource_t *rsc, GList *only_rsc,
                      gboolean check_parent)
{
    gboolean passes = FALSE;

    if (check_parent
        && pcmk__str_in_list(rsc_printable_id(pe__const_top_resource(rsc,
                                                                     false)),
                             only_rsc, pcmk__str_star_matches)) {
        passes = TRUE;
    } else if (pcmk__str_in_list(rsc_printable_id(rsc), only_rsc, pcmk__str_star_matches)) {
        passes = TRUE;
    } else if (strstr(rsc->id, ":") != NULL && pcmk__str_in_list(rsc->id, only_rsc, pcmk__str_star_matches)) {
        passes = TRUE;
    } else {
        for (const GList *iter = rsc->children;
             iter != NULL; iter = iter->next) {

            const pcmk_resource_t *child_rsc = iter->data;

            if (!child_rsc->private->fns->is_filtered(child_rsc, only_rsc,
                                                      FALSE)) {
                passes = TRUE;
                break;
            }
        }
    }

    return !passes;
}

/*!
 * \internal
 * \brief Get maximum group resource instances per node
 *
 * \param[in] rsc  Group resource to check
 *
 * \return Maximum number of \p rsc instances that can be active on one node
 */
unsigned int
pe__group_max_per_node(const pcmk_resource_t *rsc)
{
    CRM_ASSERT(pcmk__is_group(rsc));
    return 1U;
}

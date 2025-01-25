/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <limits.h>
#include <glib.h>
#include <libxml/tree.h>

#include <crm/common/ipc_attrd_internal.h>
#include <crm/common/ipc_controld.h>
#include <crm/common/lists_internal.h>
#include <crm/services_internal.h>

#include <crm_resource.h>

static GList *
build_node_info_list(const pcmk_resource_t *rsc)
{
    GList *retval = NULL;

    for (const GList *iter = rsc->priv->children;
         iter != NULL; iter = iter->next) {

        const pcmk_resource_t *child = (const pcmk_resource_t *) iter->data;

        for (const GList *iter2 = child->priv->active_nodes;
             iter2 != NULL; iter2 = iter2->next) {

            const pcmk_node_t *node = (const pcmk_node_t *) iter2->data;
            node_info_t *ni = pcmk__assert_alloc(1, sizeof(node_info_t));

            ni->node_name = node->priv->name;
            if (pcmk_is_set(rsc->flags, pcmk__rsc_promotable)
                && (child->priv->fns->state(child,
                                            TRUE) == pcmk_role_promoted)) {
                ni->promoted = true;
            }

            retval = g_list_prepend(retval, ni);
        }
    }

    return retval;
}

GList *
cli_resource_search(pcmk_resource_t *rsc, const char *requested_name,
                    pcmk_scheduler_t *scheduler)
{
    GList *retval = NULL;
    const pcmk_resource_t *parent = pe__const_top_resource(rsc, false);

    if (pcmk__is_clone(rsc)) {
        retval = build_node_info_list(rsc);

    /* The anonymous clone children's common ID is supplied */
    } else if (pcmk__is_clone(parent)
               && !pcmk_is_set(rsc->flags, pcmk__rsc_unique)
               && (rsc->priv->history_id != NULL)
               && pcmk__str_eq(requested_name, rsc->priv->history_id,
                               pcmk__str_none)
               && !pcmk__str_eq(requested_name, rsc->id, pcmk__str_none)) {

        retval = build_node_info_list(parent);

    } else {
        for (GList *iter = rsc->priv->active_nodes;
             iter != NULL; iter = iter->next) {

            pcmk_node_t *node = (pcmk_node_t *) iter->data;
            node_info_t *ni = pcmk__assert_alloc(1, sizeof(node_info_t));

            ni->node_name = node->priv->name;
            if (rsc->priv->fns->state(rsc, TRUE) == pcmk_role_promoted) {
                ni->promoted = true;
            }

            retval = g_list_prepend(retval, ni);
        }
    }

    return retval;
}

// \return Standard Pacemaker return code
static int
find_resource_attr(pcmk__output_t *out, cib_t * the_cib, const char *attr,
                   const char *rsc, const char *attr_set_type, const char *set_name,
                   const char *attr_id, const char *attr_name, xmlNode **result)
{
    xmlNode *xml_search;
    int rc = pcmk_rc_ok;
    GString *xpath = NULL;
    const char *xpath_base = NULL;

    if (result) {
        *result = NULL;
    }

    if(the_cib == NULL) {
        return ENOTCONN;
    }

    xpath_base = pcmk_cib_xpath_for(PCMK_XE_RESOURCES);
    if (xpath_base == NULL) {
        crm_err(PCMK_XE_RESOURCES " CIB element not known (bug?)");
        return ENOMSG;
    }

    xpath = g_string_sized_new(1024);
    pcmk__g_strcat(xpath,
                   xpath_base, "//*[@" PCMK_XA_ID "=\"", rsc, "\"]", NULL);

    if (attr_set_type != NULL) {
        pcmk__g_strcat(xpath, "/", attr_set_type, NULL);
        if (set_name != NULL) {
            pcmk__g_strcat(xpath, "[@" PCMK_XA_ID "=\"", set_name, "\"]",
                           NULL);
        }
    }

    g_string_append(xpath, "//" PCMK_XE_NVPAIR);

    if (attr_id != NULL && attr_name!= NULL) {
        pcmk__g_strcat(xpath,
                       "[@" PCMK_XA_ID "='", attr_id, "' "
                       "and @" PCMK_XA_NAME "='", attr_name, "']", NULL);

    } else if (attr_id != NULL) {
        pcmk__g_strcat(xpath, "[@" PCMK_XA_ID "='", attr_id, "']", NULL);

    } else if (attr_name != NULL) {
        pcmk__g_strcat(xpath, "[@" PCMK_XA_NAME "='", attr_name, "']", NULL);
    }

    rc = the_cib->cmds->query(the_cib, xpath->str, &xml_search,
                              cib_sync_call|cib_xpath);
    rc = pcmk_legacy2rc(rc);

    if (rc == pcmk_rc_ok) {
        crm_log_xml_debug(xml_search, "Match");
        if (xml_search->children != NULL) {
            rc = ENOTUNIQ;
            pcmk__warn_multiple_name_matches(out, xml_search, attr_name);
            out->spacer(out);
        }
    }

    if (result) {
        *result = xml_search;
    } else {
        pcmk__xml_free(xml_search);
    }

    g_string_free(xpath, TRUE);
    return rc;
}

/* PRIVATE. Use the find_matching_attr_resources instead. */
static void
find_matching_attr_resources_recursive(pcmk__output_t *out,
                                       GList /* <pcmk_resource_t*> */ **result,
                                       pcmk_resource_t *rsc, const char * attr_set,
                                       const char * attr_set_type, const char * attr_id,
                                       const char * attr_name, cib_t * cib, int depth)
{
    int rc = pcmk_rc_ok;
    char *lookup_id = clone_strip(rsc->id);

    for (GList *gIter = rsc->priv->children;
         gIter != NULL; gIter = gIter->next) {

        find_matching_attr_resources_recursive(out, result,
                                               (pcmk_resource_t *) gIter->data,
                                               attr_set, attr_set_type, attr_id,
                                               attr_name, cib, depth+1);
        /* do it only once for clones */
        if (pcmk__is_clone(rsc)) {
            break;
        }
    }

    rc = find_resource_attr(out, cib, PCMK_XA_ID, lookup_id, attr_set_type,
                            attr_set, attr_id, attr_name, NULL);
    /* Post-order traversal.
     * The root is always on the list and it is the last item. */
    if((0 == depth) || (pcmk_rc_ok == rc)) {
        /* push the head */
        *result = g_list_append(*result, rsc);
    }

    free(lookup_id);
}


/* The result is a linearized pre-ordered tree of resources. */
static GList/*<pcmk_resource_t*>*/ *
find_matching_attr_resources(pcmk__output_t *out, pcmk_resource_t *rsc,
                             const char * rsc_id, const char * attr_set,
                             const char * attr_set_type, const char * attr_id,
                             const char * attr_name, cib_t * cib, const char * cmd,
                             gboolean force)
{
    int rc = pcmk_rc_ok;
    char *lookup_id = NULL;
    GList * result = NULL;

    /* If --force is used, update only the requested resource (clone or primitive).
     * Otherwise, if the primitive has the attribute, use that.
     * Otherwise use the clone. */
    if(force == TRUE) {
        return g_list_append(result, rsc);
    }
    if (pcmk__is_clone(rsc->priv->parent)) {
        int rc = find_resource_attr(out, cib, PCMK_XA_ID, rsc_id, attr_set_type,
                                    attr_set, attr_id, attr_name, NULL);

        if(rc != pcmk_rc_ok) {
            rsc = rsc->priv->parent;
            out->info(out, "Performing %s of '%s' on '%s', the parent of '%s'",
                      cmd, attr_name, rsc->id, rsc_id);
        }
        return g_list_append(result, rsc);

    } else if ((rsc->priv->parent == NULL)
               && (rsc->priv->children != NULL) && pcmk__is_clone(rsc)) {

        pcmk_resource_t *child = rsc->priv->children->data;

        if (pcmk__is_primitive(child)) {
            lookup_id = clone_strip(child->id); /* Could be a cloned group! */
            rc = find_resource_attr(out, cib, PCMK_XA_ID, lookup_id,
                                    attr_set_type, attr_set, attr_id, attr_name, NULL);

            if(rc == pcmk_rc_ok) {
                rsc = child;
                out->info(out, "A value for '%s' already exists in child '%s', performing %s on that instead of '%s'",
                          attr_name, lookup_id, cmd, rsc_id);
            }

            free(lookup_id);
        }
        return g_list_append(result, rsc);
    }
    /* If the resource is a group ==> children inherit the attribute if defined. */
    find_matching_attr_resources_recursive(out, &result, rsc, attr_set,
                                           attr_set_type, attr_id, attr_name,
                                           cib, 0);
    return result;
}

/*!
 * \internal
 * \brief Get a resource's XML by resource ID from a given CIB XML tree
 *
 * \param[in] cib_xml  CIB XML to search
 * \param[in] rsc      Resource whose XML to get
 *
 * \return Subtree of \p cib_xml belonging to \p rsc, or \c NULL if not found
 */
static xmlNode *
get_cib_rsc(xmlNode *cib_xml, const pcmk_resource_t *rsc)
{
    char *xpath = crm_strdup_printf("%s//*[@" PCMK_XA_ID "='%s']",
                                    pcmk_cib_xpath_for(PCMK_XE_RESOURCES),
                                    pcmk__xe_id(rsc->priv->xml));
    xmlNode *rsc_xml = get_xpath_object(xpath, cib_xml, LOG_ERR);

    free(xpath);
    return rsc_xml;
}

static int
update_element_attribute(pcmk__output_t *out, pcmk_resource_t *rsc,
                         cib_t *cib, xmlNode *cib_xml_orig,
                         const char *attr_name, const char *attr_value)
{
    int rc = pcmk_rc_ok;
    xmlNode *rsc_xml = rsc->priv->xml;

    rsc_xml = get_cib_rsc(cib_xml_orig, rsc);
    if (rsc_xml == NULL) {
        return ENXIO;
    }

    crm_xml_add(rsc_xml, attr_name, attr_value);

    rc = cib->cmds->replace(cib, PCMK_XE_RESOURCES, rsc_xml, cib_sync_call);
    rc = pcmk_legacy2rc(rc);
    if (rc == pcmk_rc_ok) {
        out->info(out, "Set attribute: " PCMK_XA_NAME "=%s value=%s",
                  attr_name, attr_value);
    }

    return rc;
}

static int
resources_with_attr(pcmk__output_t *out, cib_t *cib, pcmk_resource_t *rsc,
                    const char *requested_name, const char *attr_set,
                    const char *attr_set_type, const char *attr_id,
                    const char *attr_name, const char *top_id, gboolean force,
                    GList **resources)
{
    if (pcmk__str_eq(attr_set_type, PCMK_XE_INSTANCE_ATTRIBUTES,
                     pcmk__str_casei)) {
        if (!force) {
            xmlNode *xml_search = NULL;
            int rc = pcmk_rc_ok;

            rc = find_resource_attr(out, cib, PCMK_XA_ID, top_id,
                                    PCMK_XE_META_ATTRIBUTES, attr_set, attr_id,
                                    attr_name, &xml_search);

            if (rc == pcmk_rc_ok || rc == ENOTUNIQ) {
                char *found_attr_id = NULL;

                found_attr_id = crm_element_value_copy(xml_search, PCMK_XA_ID);

                if (!out->is_quiet(out)) {
                    out->err(out,
                             "WARNING: There is already a meta attribute "
                             "for '%s' called '%s' (id=%s)",
                             top_id, attr_name, found_attr_id);
                    out->err(out,
                             "         Delete '%s' first or use the force option "
                             "to override", found_attr_id);
                }

                free(found_attr_id);
                pcmk__xml_free(xml_search);
                return ENOTUNIQ;
            }

            pcmk__xml_free(xml_search);
        }

        *resources = g_list_append(*resources, rsc);

    } else {
        *resources = find_matching_attr_resources(out, rsc, requested_name,
                                                  attr_set, attr_set_type,
                                                  attr_id, attr_name, cib,
                                                  "update", force);
    }

    /* If the user specified attr_set or attr_id, the intent is to modify a
     * single resource, which will be the last item in the list.
     */
    if ((attr_set != NULL) || (attr_id != NULL)) {
        GList *last = g_list_last(*resources);

        *resources = g_list_remove_link(*resources, last);
        g_list_free(*resources);
        *resources = last;
    }

    return pcmk_rc_ok;
}

static void
free_attr_update_data(gpointer data)
{
    attr_update_data_t *ud = data;

    if (ud == NULL) {
        return;
    }

    free(ud->attr_set_type);
    free(ud->attr_set_id);
    free(ud->attr_name);
    free(ud->attr_value);
    free(ud->given_rsc_id);
    free(ud->found_attr_id);
    free(ud);
}

static int
update_attribute(pcmk_resource_t *rsc, const char *requested_name,
                 const char *attr_set, const char *attr_set_type,
                 const char *attr_id, const char *attr_name,
                 const char *attr_value, gboolean recursive, cib_t *cib,
                 xmlNode *cib_xml_orig, gboolean force, GList **results)
{
    pcmk__output_t *out = rsc->priv->scheduler->priv->out;
    int rc = pcmk_rc_ok;

    GList/*<pcmk_resource_t*>*/ *resources = NULL;
    const char *top_id = pe__const_top_resource(rsc, false)->id;

    if ((attr_id == NULL) && !force) {
        find_resource_attr(out, cib, PCMK_XA_ID, top_id, NULL, NULL, NULL,
                           attr_name, NULL);
    }

    rc = resources_with_attr(out, cib, rsc, requested_name, attr_set, attr_set_type,
                             attr_id, attr_name, top_id, force, &resources);

    if (rc != pcmk_rc_ok) {
        return rc;
    }

    for (GList *iter = resources; iter != NULL; iter = iter->next) {
        // @TODO Functionize loop body to simplify freeing allocated memory
        char *lookup_id = NULL;
        char *local_attr_set = NULL;
        char *found_attr_id = NULL;
        const char *rsc_attr_id = attr_id;
        const char *rsc_attr_set = attr_set;

        xmlNode *rsc_xml = rsc->priv->xml;
        xmlNode *xml_top = NULL;
        xmlNode *xml_obj = NULL;
        xmlNode *xml_search = NULL;

        rsc = (pcmk_resource_t *) iter->data;

        lookup_id = clone_strip(rsc->id); /* Could be a cloned group! */
        rc = find_resource_attr(out, cib, PCMK_XA_ID, lookup_id, attr_set_type,
                                attr_set, attr_id, attr_name, &xml_search);

        switch (rc) {
            case pcmk_rc_ok:
                found_attr_id = crm_element_value_copy(xml_search, PCMK_XA_ID);
                crm_debug("Found a match for " PCMK_XA_NAME "='%s': "
                          PCMK_XA_ID "='%s'", attr_name, found_attr_id);
                rsc_attr_id = found_attr_id;
                break;

            case ENXIO:
                if (rsc_attr_set == NULL) {
                    local_attr_set = crm_strdup_printf("%s-%s", lookup_id,
                                                       attr_set_type);
                    rsc_attr_set = local_attr_set;
                }
                if (rsc_attr_id == NULL) {
                    found_attr_id = crm_strdup_printf("%s-%s",
                                                      rsc_attr_set, attr_name);
                    rsc_attr_id = found_attr_id;
                }

                rsc_xml = get_cib_rsc(cib_xml_orig, rsc);
                if (rsc_xml == NULL) {
                    /* @TODO Warn and continue through the rest of the resources
                     * and return the error at the end? This should never
                     * happen, but if it does, then we could have a partial
                     * update.
                     */
                    free(lookup_id);
                    free(found_attr_id);
                    pcmk__xml_free(xml_search);
                    g_list_free(resources);
                    return ENXIO;
                }

                xml_top = pcmk__xe_create(NULL, (const char *) rsc_xml->name);
                crm_xml_add(xml_top, PCMK_XA_ID, lookup_id);

                xml_obj = pcmk__xe_create(xml_top, attr_set_type);
                crm_xml_add(xml_obj, PCMK_XA_ID, rsc_attr_set);
                break;

            default:
                free(lookup_id);
                free(found_attr_id);
                pcmk__xml_free(xml_search);
                g_list_free(resources);
                return rc;
        }

        xml_obj = crm_create_nvpair_xml(xml_obj, rsc_attr_id, attr_name,
                                        attr_value);
        if (xml_top == NULL) {
            xml_top = xml_obj;
        }

        crm_log_xml_debug(xml_top, "Update");

        rc = cib->cmds->modify(cib, PCMK_XE_RESOURCES, xml_top, cib_sync_call);
        rc = pcmk_legacy2rc(rc);
        if (rc == pcmk_rc_ok) {
            attr_update_data_t *ud = pcmk__assert_alloc(1, sizeof(attr_update_data_t));

            if (attr_set_type == NULL) {
                attr_set_type = (const char *) xml_search->parent->name;
            }

            if (rsc_attr_set == NULL) {
                rsc_attr_set = crm_element_value(xml_search->parent, PCMK_XA_ID);
            }

            ud->attr_set_type = pcmk__str_copy(attr_set_type);
            ud->attr_set_id = pcmk__str_copy(rsc_attr_set);
            ud->attr_name = pcmk__str_copy(attr_name);
            ud->attr_value = pcmk__str_copy(attr_value);
            ud->given_rsc_id = pcmk__str_copy(lookup_id);
            ud->found_attr_id = pcmk__str_copy(found_attr_id);
            ud->rsc = rsc;

            *results = g_list_append(*results, ud);
        }

        pcmk__xml_free(xml_top);
        pcmk__xml_free(xml_search);

        free(lookup_id);
        free(found_attr_id);
        free(local_attr_set);

        if (recursive
            && pcmk__str_eq(attr_set_type, PCMK_XE_META_ATTRIBUTES,
                            pcmk__str_casei)) {
            /* We want to set the attribute only on resources explicitly
             * colocated with this one, so we use
             * rsc->priv->with_this_colocations directly rather than the
             * with_this_colocations() method.
             */
            pcmk__set_rsc_flags(rsc, pcmk__rsc_detect_loop);
            for (GList *lpc = rsc->priv->with_this_colocations;
                 lpc != NULL; lpc = lpc->next) {
                pcmk__colocation_t *cons = (pcmk__colocation_t *) lpc->data;

                crm_debug("Checking %s %d", cons->id, cons->score);

                if (pcmk_is_set(cons->dependent->flags, pcmk__rsc_detect_loop)
                    || (cons->score <= 0)) {
                    continue;
                }

                crm_debug("Setting %s=%s for dependent resource %s",
                          attr_name, attr_value, cons->dependent->id);
                update_attribute(cons->dependent, cons->dependent->id, NULL,
                                 attr_set_type, NULL, attr_name, attr_value,
                                 recursive, cib, cib_xml_orig, force, results);
            }
        }
    }

    g_list_free(resources);
    return rc;
}

// \return Standard Pacemaker return code
int
cli_resource_update_attribute(pcmk_resource_t *rsc, const char *requested_name,
                              const char *attr_set, const char *attr_set_type,
                              const char *attr_id, const char *attr_name,
                              const char *attr_value, gboolean recursive,
                              cib_t *cib, xmlNode *cib_xml_orig, gboolean force)
{
    static bool need_init = true;
    int rc = pcmk_rc_ok;

    GList *results = NULL;
    pcmk__output_t *out = rsc->priv->scheduler->priv->out;

    pcmk__assert(cib_xml_orig != NULL);

    /* If we were asked to update the attribute in a resource element (for
     * instance, <primitive class="ocf">) there's really not much we need to do.
     */
    if (pcmk__str_eq(attr_set_type, ATTR_SET_ELEMENT, pcmk__str_none)) {
        return update_element_attribute(out, rsc, cib, cib_xml_orig, attr_name,
                                        attr_value);
    }

    /* One time initialization - clear flags so we can detect loops */
    if (need_init) {
        need_init = false;
        pcmk__unpack_constraints(rsc->priv->scheduler);
        pe__clear_resource_flags_on_all(rsc->priv->scheduler,
                                        pcmk__rsc_detect_loop);
    }

    rc = update_attribute(rsc, requested_name, attr_set, attr_set_type,
                          attr_id, attr_name, attr_value, recursive, cib,
                          cib_xml_orig, force, &results);

    if (rc == pcmk_rc_ok) {
        if (results == NULL) {
            return rc;
        }

        out->message(out, "attribute-changed-list", results);
        g_list_free_full(results, free_attr_update_data);
    }

    return rc;
}

// \return Standard Pacemaker return code
int
cli_resource_delete_attribute(pcmk_resource_t *rsc, const char *requested_name,
                              const char *attr_set, const char *attr_set_type,
                              const char *attr_id, const char *attr_name,
                              cib_t *cib, xmlNode *cib_xml_orig, gboolean force)
{
    pcmk__output_t *out = rsc->priv->scheduler->priv->out;
    int rc = pcmk_rc_ok;
    GList/*<pcmk_resource_t*>*/ *resources = NULL;

    pcmk__assert((cib != NULL) && (cib_xml_orig != NULL));

    if ((attr_id == NULL) && !force) {
        find_resource_attr(out, cib, PCMK_XA_ID,
                           pe__const_top_resource(rsc, false)->id, NULL,
                           NULL, NULL, attr_name, NULL);
    }

    if (pcmk__str_eq(attr_set_type, ATTR_SET_ELEMENT, pcmk__str_none)) {
        xmlNode *rsc_xml = rsc->priv->xml;

        rsc_xml = get_cib_rsc(cib_xml_orig, rsc);
        if (rsc_xml == NULL) {
            return ENXIO;
        }

        pcmk__xe_remove_attr(rsc_xml, attr_name);
        rc = cib->cmds->replace(cib, PCMK_XE_RESOURCES, rsc_xml, cib_sync_call);
        rc = pcmk_legacy2rc(rc);
        if (rc == pcmk_rc_ok) {
            out->info(out, "Deleted attribute: %s", attr_name);
        }
        return rc;
    }

    if (pcmk__str_eq(attr_set_type, PCMK_XE_META_ATTRIBUTES, pcmk__str_none)) {
        resources = find_matching_attr_resources(out, rsc, requested_name,
                                                 attr_set, attr_set_type,
                                                 attr_id, attr_name, cib,
                                                 "delete", force);
    } else {
        resources = g_list_append(resources, rsc);
    }

    for (GList *iter = resources; iter != NULL; iter = iter->next) {
        char *lookup_id = NULL;
        xmlNode *xml_obj = NULL;
        xmlNode *xml_search = NULL;
        char *found_attr_id = NULL;
        const char *rsc_attr_id = attr_id;

        rsc = (pcmk_resource_t *) iter->data;

        /* @TODO Search the original CIB in find_resource_attr() for
         * future-proofing, to ensure that we're getting IDs of nvpairs that
         * exist in the CIB.
         */
        lookup_id = clone_strip(rsc->id);
        rc = find_resource_attr(out, cib, PCMK_XA_ID, lookup_id, attr_set_type,
                                attr_set, attr_id, attr_name, &xml_search);
        switch (rc) {
            case pcmk_rc_ok:
                found_attr_id = crm_element_value_copy(xml_search, PCMK_XA_ID);
                pcmk__xml_free(xml_search);
                break;

            case ENXIO:
                free(lookup_id);
                pcmk__xml_free(xml_search);
                continue;

            default:
                free(lookup_id);
                pcmk__xml_free(xml_search);
                g_list_free(resources);
                return rc;
        }

        if (rsc_attr_id == NULL) {
            rsc_attr_id = found_attr_id;
        }

        xml_obj = crm_create_nvpair_xml(NULL, rsc_attr_id, attr_name, NULL);
        crm_log_xml_debug(xml_obj, "Delete");

        rc = cib->cmds->remove(cib, PCMK_XE_RESOURCES, xml_obj, cib_sync_call);
        rc = pcmk_legacy2rc(rc);

        if (rc == pcmk_rc_ok) {
            out->info(out, "Deleted '%s' option: " PCMK_XA_ID "=%s%s%s%s%s",
                      lookup_id, found_attr_id,
                      ((attr_set == NULL)? "" : " set="),
                      pcmk__s(attr_set, ""),
                      ((attr_name == NULL)? "" : " " PCMK_XA_NAME "="),
                      pcmk__s(attr_name, ""));
        }

        free(lookup_id);
        pcmk__xml_free(xml_obj);
        free(found_attr_id);
    }

    g_list_free(resources);
    return rc;
}

// \return Standard Pacemaker return code
static int
send_lrm_rsc_op(pcmk_ipc_api_t *controld_api, bool do_fail_resource,
                const char *host_uname, const char *rsc_id,
                pcmk_scheduler_t *scheduler)
{
    pcmk__output_t *out = scheduler->priv->out;
    const char *router_node = host_uname;
    const char *rsc_api_id = NULL;
    const char *rsc_long_id = NULL;
    const char *rsc_class = NULL;
    const char *rsc_provider = NULL;
    const char *rsc_type = NULL;
    bool cib_only = false;
    pcmk_resource_t *rsc = pe_find_resource(scheduler->priv->resources, rsc_id);

    if (rsc == NULL) {
        out->err(out, "Resource %s not found", rsc_id);
        return ENXIO;

    } else if (!pcmk__is_primitive(rsc)) {
        out->err(out, "We can only process primitive resources, not %s", rsc_id);
        return EINVAL;
    }

    rsc_class = crm_element_value(rsc->priv->xml, PCMK_XA_CLASS);
    rsc_provider = crm_element_value(rsc->priv->xml, PCMK_XA_PROVIDER);
    rsc_type = crm_element_value(rsc->priv->xml, PCMK_XA_TYPE);
    if ((rsc_class == NULL) || (rsc_type == NULL)) {
        out->err(out, "Resource %s does not have a class and type", rsc_id);
        return EINVAL;
    }

    {
        pcmk_node_t *node = pcmk_find_node(scheduler, host_uname);

        if (node == NULL) {
            out->err(out, "Node %s not found", host_uname);
            return pcmk_rc_node_unknown;
        }

        if (!(node->details->online)) {
            if (do_fail_resource) {
                out->err(out, "Node %s is not online", host_uname);
                return ENOTCONN;
            } else {
                cib_only = true;
            }
        }
        if (!cib_only && pcmk__is_pacemaker_remote_node(node)) {
            node = pcmk__current_node(node->priv->remote);
            if (node == NULL) {
                out->err(out, "No cluster connection to Pacemaker Remote node %s detected",
                         host_uname);
                return ENOTCONN;
            }
            router_node = node->priv->name;
        }
    }

    if (rsc->priv->history_id != NULL) {
        rsc_api_id = rsc->priv->history_id;
        rsc_long_id = rsc->id;
    } else {
        rsc_api_id = rsc->id;
    }
    if (do_fail_resource) {
        return pcmk_controld_api_fail(controld_api, host_uname, router_node,
                                      rsc_api_id, rsc_long_id,
                                      rsc_class, rsc_provider, rsc_type);
    } else {
        return pcmk_controld_api_refresh(controld_api, host_uname, router_node,
                                         rsc_api_id, rsc_long_id, rsc_class,
                                         rsc_provider, rsc_type, cib_only);
    }
}

/*!
 * \internal
 * \brief Get resource name as used in failure-related node attributes
 *
 * \param[in] rsc  Resource to check
 *
 * \return Newly allocated string containing resource's fail name
 * \note The caller is responsible for freeing the result.
 */
static inline char *
rsc_fail_name(const pcmk_resource_t *rsc)
{
    const char *name = pcmk__s(rsc->priv->history_id, rsc->id);

    if (pcmk_is_set(rsc->flags, pcmk__rsc_unique)) {
        return strdup(name);
    }
    return clone_strip(name);
}

// \return Standard Pacemaker return code
static int
clear_rsc_history(pcmk_ipc_api_t *controld_api, const char *host_uname,
                  const char *rsc_id, pcmk_scheduler_t *scheduler)
{
    int rc = pcmk_rc_ok;

    /* Erase the resource's entire LRM history in the CIB, even if we're only
     * clearing a single operation's fail count. If we erased only entries for a
     * single operation, we might wind up with a wrong idea of the current
     * resource state, and we might not re-probe the resource.
     */
    rc = send_lrm_rsc_op(controld_api, false, host_uname, rsc_id, scheduler);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    crm_trace("Processing %d mainloop inputs",
              pcmk_controld_api_replies_expected(controld_api));
    while (g_main_context_iteration(NULL, FALSE)) {
        crm_trace("Processed mainloop input, %d still remaining",
                  pcmk_controld_api_replies_expected(controld_api));
    }
    return rc;
}

// \return Standard Pacemaker return code
static int
clear_rsc_failures(pcmk__output_t *out, pcmk_ipc_api_t *controld_api,
                   const char *node_name, const char *rsc_id, const char *operation,
                   const char *interval_spec, pcmk_scheduler_t *scheduler)
{
    int rc = pcmk_rc_ok;
    const char *failed_value = NULL;
    const char *failed_id = NULL;
    char *interval_ms_s = NULL;
    GHashTable *rscs = NULL;
    GHashTableIter iter;

    /* Create a hash table to use as a set of resources to clean. This lets us
     * clean each resource only once (per node) regardless of how many failed
     * operations it has.
     */
    rscs = pcmk__strkey_table(NULL, NULL);

    // Normalize interval to milliseconds for comparison to history entry
    if (operation) {
        guint interval_ms = 0U;

        pcmk_parse_interval_spec(interval_spec, &interval_ms);
        interval_ms_s = crm_strdup_printf("%u", interval_ms);
    }

    for (xmlNode *xml_op = pcmk__xe_first_child(scheduler->priv->failed, NULL,
                                                NULL, NULL);
         xml_op != NULL; xml_op = pcmk__xe_next(xml_op, NULL)) {

        failed_id = crm_element_value(xml_op, PCMK__XA_RSC_ID);
        if (failed_id == NULL) {
            // Malformed history entry, should never happen
            continue;
        }

        // No resource specified means all resources match
        if (rsc_id) {
            pcmk_resource_t *fail_rsc = NULL;

            fail_rsc = pe_find_resource_with_flags(scheduler->priv->resources,
                                                   failed_id,
                                                   pcmk_rsc_match_history
                                                   |pcmk_rsc_match_anon_basename);
            if ((fail_rsc == NULL)
                || !pcmk__str_eq(rsc_id, fail_rsc->id, pcmk__str_none)) {
                continue;
            }
        }

        // Host name should always have been provided by this point
        failed_value = crm_element_value(xml_op, PCMK_XA_UNAME);
        if (!pcmk__str_eq(node_name, failed_value, pcmk__str_casei)) {
            continue;
        }

        // No operation specified means all operations match
        if (operation) {
            failed_value = crm_element_value(xml_op, PCMK_XA_OPERATION);
            if (!pcmk__str_eq(operation, failed_value, pcmk__str_casei)) {
                continue;
            }

            // Interval (if operation was specified) defaults to 0 (not all)
            failed_value = crm_element_value(xml_op, PCMK_META_INTERVAL);
            if (!pcmk__str_eq(interval_ms_s, failed_value, pcmk__str_casei)) {
                continue;
            }
        }

        g_hash_table_add(rscs, (gpointer) failed_id);
    }

    free(interval_ms_s);

    g_hash_table_iter_init(&iter, rscs);
    while (g_hash_table_iter_next(&iter, (gpointer *) &failed_id, NULL)) {
        crm_debug("Erasing failures of %s on %s", failed_id, node_name);
        rc = clear_rsc_history(controld_api, node_name, failed_id, scheduler);
        if (rc != pcmk_rc_ok) {
            return rc;
        }
    }
    g_hash_table_destroy(rscs);
    return rc;
}

// \return Standard Pacemaker return code
static int
clear_rsc_fail_attrs(const pcmk_resource_t *rsc, const char *operation,
                     const char *interval_spec, const pcmk_node_t *node)
{
    int rc = pcmk_rc_ok;
    int attr_options = pcmk__node_attr_none;
    char *rsc_name = rsc_fail_name(rsc);

    if (pcmk__is_pacemaker_remote_node(node)) {
        attr_options |= pcmk__node_attr_remote;
    }

    rc = pcmk__attrd_api_clear_failures(NULL, node->priv->name, rsc_name,
                                        operation, interval_spec, NULL,
                                        attr_options);
    free(rsc_name);
    return rc;
}

// \return Standard Pacemaker return code
int
cli_resource_delete(pcmk_ipc_api_t *controld_api, const char *host_uname,
                    const pcmk_resource_t *rsc, const char *operation,
                    const char *interval_spec, bool just_failures,
                    pcmk_scheduler_t *scheduler, gboolean force)
{
    pcmk__output_t *out = scheduler->priv->out;
    int rc = pcmk_rc_ok;
    pcmk_node_t *node = NULL;

    if (rsc == NULL) {
        return ENXIO;

    } else if (rsc->priv->children != NULL) {

        for (const GList *lpc = rsc->priv->children;
             lpc != NULL; lpc = lpc->next) {

            const pcmk_resource_t *child = (const pcmk_resource_t *) lpc->data;

            rc = cli_resource_delete(controld_api, host_uname, child, operation,
                                     interval_spec, just_failures, scheduler,
                                     force);
            if (rc != pcmk_rc_ok) {
                return rc;
            }
        }
        return pcmk_rc_ok;

    } else if (host_uname == NULL) {
        GList *lpc = NULL;
        GList *nodes = g_hash_table_get_values(rsc->priv->probed_nodes);

        if(nodes == NULL && force) {
            nodes = pcmk__copy_node_list(scheduler->nodes, false);

        } else if ((nodes == NULL)
                   && pcmk_is_set(rsc->flags, pcmk__rsc_exclusive_probes)) {
            GHashTableIter iter;
            pcmk_node_t *node = NULL;

            g_hash_table_iter_init(&iter, rsc->priv->allowed_nodes);
            while (g_hash_table_iter_next(&iter, NULL, (void**)&node)) {
                if (node->assign->score >= 0) {
                    nodes = g_list_prepend(nodes, node);
                }
            }

        } else if(nodes == NULL) {
            nodes = g_hash_table_get_values(rsc->priv->allowed_nodes);
        }

        for (lpc = nodes; lpc != NULL; lpc = lpc->next) {
            node = (pcmk_node_t *) lpc->data;

            if (node->details->online) {
                rc = cli_resource_delete(controld_api, node->priv->name, rsc,
                                         operation, interval_spec, just_failures,
                                         scheduler, force);
            }
            if (rc != pcmk_rc_ok) {
                g_list_free(nodes);
                return rc;
            }
        }

        g_list_free(nodes);
        return pcmk_rc_ok;
    }

    node = pcmk_find_node(scheduler, host_uname);

    if (node == NULL) {
        out->err(out, "Unable to clean up %s because node %s not found",
                 rsc->id, host_uname);
        return ENODEV;
    }

    if (!pcmk_is_set(node->priv->flags, pcmk__node_probes_allowed)) {
        out->err(out, "Unable to clean up %s because resource discovery disabled on %s",
                 rsc->id, host_uname);
        return EOPNOTSUPP;
    }

    if (controld_api == NULL) {
        out->err(out, "Dry run: skipping clean-up of %s on %s due to CIB_file",
                 rsc->id, host_uname);
        return pcmk_rc_ok;
    }

    rc = clear_rsc_fail_attrs(rsc, operation, interval_spec, node);
    if (rc != pcmk_rc_ok) {
        out->err(out, "Unable to clean up %s failures on %s: %s",
                 rsc->id, host_uname, pcmk_rc_str(rc));
        return rc;
    }

    if (just_failures) {
        rc = clear_rsc_failures(out, controld_api, host_uname, rsc->id, operation,
                                interval_spec, scheduler);
    } else {
        rc = clear_rsc_history(controld_api, host_uname, rsc->id, scheduler);
    }
    if (rc != pcmk_rc_ok) {
        out->err(out, "Cleaned %s failures on %s, but unable to clean history: %s",
                 rsc->id, host_uname, pcmk_rc_str(rc));
    } else {
        out->info(out, "Cleaned up %s on %s", rsc->id, host_uname);
    }
    return rc;
}

// \return Standard Pacemaker return code
int
cli_cleanup_all(pcmk_ipc_api_t *controld_api, const char *node_name,
                const char *operation, const char *interval_spec,
                pcmk_scheduler_t *scheduler)
{
    pcmk__output_t *out = scheduler->priv->out;
    int rc = pcmk_rc_ok;
    int attr_options = pcmk__node_attr_none;
    const char *display_name = node_name? node_name : "all nodes";

    if (controld_api == NULL) {
        out->info(out, "Dry run: skipping clean-up of %s due to CIB_file",
                  display_name);
        return rc;
    }

    if (node_name) {
        pcmk_node_t *node = pcmk_find_node(scheduler, node_name);

        if (node == NULL) {
            out->err(out, "Unknown node: %s", node_name);
            return ENXIO;
        }
        if (pcmk__is_pacemaker_remote_node(node)) {
            attr_options |= pcmk__node_attr_remote;
        }
    }

    rc = pcmk__attrd_api_clear_failures(NULL, node_name, NULL, operation,
                                        interval_spec, NULL, attr_options);
    if (rc != pcmk_rc_ok) {
        out->err(out, "Unable to clean up all failures on %s: %s",
                 display_name, pcmk_rc_str(rc));
        return rc;
    }

    if (node_name) {
        rc = clear_rsc_failures(out, controld_api, node_name, NULL,
                                operation, interval_spec, scheduler);
        if (rc != pcmk_rc_ok) {
            out->err(out, "Cleaned all resource failures on %s, but unable to clean history: %s",
                     node_name, pcmk_rc_str(rc));
            return rc;
        }
    } else {
        for (GList *iter = scheduler->nodes; iter; iter = iter->next) {
            pcmk_node_t *node = (pcmk_node_t *) iter->data;

            rc = clear_rsc_failures(out, controld_api, node->priv->name,
                                    NULL, operation, interval_spec, scheduler);
            if (rc != pcmk_rc_ok) {
                out->err(out, "Cleaned all resource failures on all nodes, but unable to clean history: %s",
                         pcmk_rc_str(rc));
                return rc;
            }
        }
    }

    out->info(out, "Cleaned up all resources on %s", display_name);
    return rc;
}

static void
check_role(resource_checks_t *checks)
{
    const char *role_s = g_hash_table_lookup(checks->rsc->priv->meta,
                                             PCMK_META_TARGET_ROLE);

    if (role_s == NULL) {
        return;
    }
    switch (pcmk_parse_role(role_s)) {
        case pcmk_role_stopped:
            checks->flags |= rsc_remain_stopped;
            break;

        case pcmk_role_unpromoted:
            if (pcmk_is_set(pe__const_top_resource(checks->rsc, false)->flags,
                            pcmk__rsc_promotable)) {
                checks->flags |= rsc_unpromotable;
            }
            break;

        default:
            break;
    }
}

static void
check_managed(resource_checks_t *checks)
{
    const char *managed_s = g_hash_table_lookup(checks->rsc->priv->meta,
                                                PCMK_META_IS_MANAGED);

    if ((managed_s != NULL) && !crm_is_true(managed_s)) {
        checks->flags |= rsc_unmanaged;
    }
}

static void
check_locked(resource_checks_t *checks)
{
    const pcmk_node_t *lock_node = checks->rsc->priv->lock_node;

    if (lock_node != NULL) {
        checks->flags |= rsc_locked;
        checks->lock_node = lock_node->priv->name;
    }
}

static bool
node_is_unhealthy(pcmk_node_t *node)
{
    switch (pe__health_strategy(node->priv->scheduler)) {
        case pcmk__health_strategy_none:
            break;

        case pcmk__health_strategy_no_red:
            if (pe__node_health(node) < 0) {
                return true;
            }
            break;

        case pcmk__health_strategy_only_green:
            if (pe__node_health(node) <= 0) {
                return true;
            }
            break;

        case pcmk__health_strategy_progressive:
        case pcmk__health_strategy_custom:
            /* @TODO These are finite scores, possibly with rules, and possibly
             * combining with other scores, so attributing these as a cause is
             * nontrivial.
             */
            break;
    }
    return false;
}

static void
check_node_health(resource_checks_t *checks, pcmk_node_t *node)
{
    if (node == NULL) {
        GHashTableIter iter;
        bool allowed = false;
        bool all_nodes_unhealthy = true;

        g_hash_table_iter_init(&iter, checks->rsc->priv->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **) &node)) {
            allowed = true;
            if (!node_is_unhealthy(node)) {
                all_nodes_unhealthy = false;
                break;
            }
        }
        if (allowed && all_nodes_unhealthy) {
            checks->flags |= rsc_node_health;
        }

    } else if (node_is_unhealthy(node)) {
        checks->flags |= rsc_node_health;
    }
}

/* @TODO Make this check all resources if rsc is NULL, so it can be called after
 * cleanup of all resources
 */
int
cli_resource_check(pcmk__output_t *out, pcmk_resource_t *rsc, pcmk_node_t *node)
{
    resource_checks_t checks = { .rsc = rsc };

    check_role(&checks);
    check_managed(&checks);
    check_locked(&checks);
    check_node_health(&checks, node);

    return out->message(out, "resource-check-list", &checks);
}

// \return Standard Pacemaker return code
int
cli_resource_fail(pcmk_ipc_api_t *controld_api, const char *host_uname,
                  const char *rsc_id, pcmk_scheduler_t *scheduler)
{
    crm_notice("Failing %s on %s", rsc_id, host_uname);
    return send_lrm_rsc_op(controld_api, true, host_uname, rsc_id, scheduler);
}

static GHashTable *
generate_resource_params(pcmk_resource_t *rsc, pcmk_node_t *node,
                         pcmk_scheduler_t *scheduler)
{
    GHashTable *params = NULL;
    GHashTable *meta = NULL;
    GHashTable *combined = NULL;
    GHashTableIter iter;
    char *key = NULL;
    char *value = NULL;

    combined = pcmk__strkey_table(free, free);

    params = pe_rsc_params(rsc, node, scheduler);
    if (params != NULL) {
        g_hash_table_iter_init(&iter, params);
        while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
            pcmk__insert_dup(combined, key, value);
        }
    }

    meta = pcmk__strkey_table(free, free);
    get_meta_attributes(meta, rsc, NULL, scheduler);
    if (meta != NULL) {
        g_hash_table_iter_init(&iter, meta);
        while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
            char *crm_name = crm_meta_name(key);

            g_hash_table_insert(combined, crm_name, strdup(value));
        }
        g_hash_table_destroy(meta);
    }

    return combined;
}

bool resource_is_running_on(pcmk_resource_t *rsc, const char *host)
{
    bool found = true;
    GList *hIter = NULL;
    GList *hosts = NULL;

    if (rsc == NULL) {
        return false;
    }

    rsc->priv->fns->location(rsc, &hosts, pcmk__rsc_node_current);
    for (hIter = hosts; host != NULL && hIter != NULL; hIter = hIter->next) {
        pcmk_node_t *node = (pcmk_node_t *) hIter->data;

        if (pcmk__strcase_any_of(host, node->priv->name, node->priv->id,
                                 NULL)) {
            crm_trace("Resource %s is running on %s\n", rsc->id, host);
            goto done;
        }
    }

    if (host != NULL) {
        crm_trace("Resource %s is not running on: %s\n", rsc->id, host);
        found = false;

    } else if(host == NULL && hosts == NULL) {
        crm_trace("Resource %s is not running\n", rsc->id);
        found = false;
    }

  done:
    g_list_free(hosts);
    return found;
}

/*!
 * \internal
 * \brief Create a list of all resources active on host from a given list
 *
 * \param[in] host      Name of host to check whether resources are active
 * \param[in] rsc_list  List of resources to check
 *
 * \return New list of resources from list that are active on host
 */
static GList *
get_active_resources(const char *host, GList *rsc_list)
{
    GList *rIter = NULL;
    GList *active = NULL;

    for (rIter = rsc_list; rIter != NULL; rIter = rIter->next) {
        pcmk_resource_t *rsc = (pcmk_resource_t *) rIter->data;

        /* Expand groups to their members, because if we're restarting a member
         * other than the first, we can't otherwise tell which resources are
         * stopping and starting.
         */
        if (pcmk__is_group(rsc)) {
            GList *member_active = NULL;

            member_active = get_active_resources(host, rsc->priv->children);
            active = g_list_concat(active, member_active);
        } else if (resource_is_running_on(rsc, host)) {
            active = g_list_append(active, strdup(rsc->id));
        }
    }
    return active;
}

static void dump_list(GList *items, const char *tag)
{
    int lpc = 0;
    GList *item = NULL;

    for (item = items; item != NULL; item = item->next) {
        crm_trace("%s[%d]: %s", tag, lpc, (char*)item->data);
        lpc++;
    }
}

static void display_list(pcmk__output_t *out, GList *items, const char *tag)
{
    GList *item = NULL;

    for (item = items; item != NULL; item = item->next) {
        out->info(out, "%s%s", tag, (const char *)item->data);
    }
}

/*!
 * \internal
 * \brief Update scheduler XML input based on a CIB query and the current time
 *
 * The CIB XML is upgraded to the latest schema version.
 *
 * \param[in,out] out           Output object
 * \param[in,out] scheduler     Scheduler data to update
 * \param[in]     cib           Connection to the CIB manager
 * \param[out]    cib_xml_orig  Where to store CIB XML before any schema
 *                              upgrades (can be \c NULL)
 *
 * \return Standard Pacemaker return code
 */
int
update_scheduler_input(pcmk__output_t *out, pcmk_scheduler_t *scheduler,
                       cib_t *cib, xmlNode **cib_xml_orig)
{
    xmlNode *queried_xml = NULL;
    xmlNode *updated_xml = NULL;
    int rc = pcmk_rc_ok;

    pcmk__assert((out != NULL) && (scheduler != NULL)
                 && (scheduler->input == NULL) && (scheduler->priv->now == NULL)
                 && (cib != NULL)
                 && ((cib_xml_orig == NULL) || (*cib_xml_orig == NULL)));

    rc = cib->cmds->query(cib, NULL, &queried_xml, cib_sync_call);
    rc = pcmk_legacy2rc(rc);
    if (rc != pcmk_rc_ok) {
        out->err(out, "Could not obtain the current CIB: %s", pcmk_rc_str(rc));
        goto done;
    }

    if (cib_xml_orig != NULL) {
        updated_xml = pcmk__xml_copy(NULL, queried_xml);
    } else {
        // No need to preserve the pre-upgrade CIB, so don't make a copy
        updated_xml = queried_xml;
        queried_xml = NULL;
    }

    rc = pcmk__update_configured_schema(&updated_xml, false);
    if (rc != pcmk_rc_ok) {
        out->err(out, "Could not upgrade the current CIB XML: %s",
                 pcmk_rc_str(rc));
        pcmk__xml_free(updated_xml);
        goto done;
    }

    scheduler->input = updated_xml;
    scheduler->priv->now = crm_time_new(NULL);

done:
    if ((rc == pcmk_rc_ok) && (cib_xml_orig != NULL)) {
        *cib_xml_orig = queried_xml;
    } else {
        pcmk__xml_free(queried_xml);
    }
    return rc;
}

// \return Standard Pacemaker return code
static int
update_dataset(cib_t *cib, pcmk_scheduler_t *scheduler, xmlNode **cib_xml_orig,
               bool simulate)
{
    char *pid = NULL;
    char *shadow_file = NULL;
    cib_t *shadow_cib = NULL;
    int rc = pcmk_rc_ok;

    pcmk__output_t *out = scheduler->priv->out;

    pcmk_reset_scheduler(scheduler);
    pcmk__set_scheduler_flags(scheduler, pcmk__sched_no_counts);

    if(simulate) {
        bool prev_quiet = false;

        rc = update_scheduler_input(out, scheduler, cib, NULL);
        if (rc != pcmk_rc_ok) {
            goto done;
        }

        pid = pcmk__getpid_s();
        shadow_cib = cib_shadow_new(pid);
        shadow_file = get_shadow_file(pid);

        if (shadow_cib == NULL) {
            out->err(out, "Could not create shadow cib: '%s'", pid);
            rc = ENXIO;
            goto done;
        }

        rc = pcmk__xml_write_file(scheduler->input, shadow_file, false);
        if (rc != pcmk_rc_ok) {
            out->err(out, "Could not populate shadow cib: %s", pcmk_rc_str(rc));
            goto done;
        }

        rc = shadow_cib->cmds->signon(shadow_cib, crm_system_name, cib_command);
        rc = pcmk_legacy2rc(rc);

        if (rc != pcmk_rc_ok) {
            out->err(out, "Could not connect to shadow cib: %s",
                     pcmk_rc_str(rc));
            goto done;
        }

        cluster_status(scheduler);
        pcmk__schedule_actions(NULL, pcmk__sched_none, scheduler);

        prev_quiet = out->is_quiet(out);
        out->quiet = true;
        pcmk__simulate_transition(scheduler, shadow_cib, NULL);
        out->quiet = prev_quiet;

        rc = update_dataset(shadow_cib, scheduler, cib_xml_orig, false);

    } else {
        xmlNode *xml = NULL;

        rc = update_scheduler_input(out, scheduler, cib, &xml);
        if (rc != pcmk_rc_ok) {
            goto done;
        }

        pcmk__xml_free(*cib_xml_orig);
        *cib_xml_orig = xml;
        cluster_status(scheduler);
    }

  done:
    // Do not free scheduler->input because rsc->priv->xml must remain valid
    cib_delete(shadow_cib);
    free(pid);

    if(shadow_file) {
        unlink(shadow_file);
        free(shadow_file);
    }

    return rc;
}

/*!
 * \internal
 * \brief Find the maximum stop timeout of a resource and its children (if any)
 *
 * \param[in,out] rsc  Resource to get timeout for
 *
 * \return Maximum stop timeout for \p rsc (in milliseconds)
 */
static guint
max_rsc_stop_timeout(pcmk_resource_t *rsc)
{
    long long result_ll;
    guint max_delay = 0;
    xmlNode *config = NULL;
    GHashTable *meta = NULL;

    if (rsc == NULL) {
        return 0;
    }

    // If resource is collective, use maximum of its children's stop timeouts
    if (rsc->priv->children != NULL) {

        for (GList *iter = rsc->priv->children;
             iter != NULL; iter = iter->next) {

            pcmk_resource_t *child = iter->data;
            guint delay = max_rsc_stop_timeout(child);

            if (delay > max_delay) {
                pcmk__rsc_trace(rsc,
                                "Maximum stop timeout for %s is now %s "
                                "due to %s", rsc->id,
                                pcmk__readable_interval(delay), child->id);
                max_delay = delay;
            }
        }
        return max_delay;
    }

    // Get resource's stop action configuration from CIB
    config = pcmk__find_action_config(rsc, PCMK_ACTION_STOP, 0, true);

    /* Get configured timeout for stop action (fully evaluated for rules,
     * defaults, etc.).
     *
     * @TODO This currently ignores node (which might matter for rules)
     */
    meta = pcmk__unpack_action_meta(rsc, NULL, PCMK_ACTION_STOP, 0, config);
    if ((pcmk__scan_ll(g_hash_table_lookup(meta, PCMK_META_TIMEOUT),
                       &result_ll, -1LL) == pcmk_rc_ok) && (result_ll >= 0)) {
        max_delay = (guint) QB_MIN(result_ll, UINT_MAX);
    }
    g_hash_table_destroy(meta);

    return max_delay;
}

/*!
 * \internal
 * \brief Find a reasonable waiting time for stopping any one resource in a list
 *
 * \param[in,out] scheduler  Scheduler data
 * \param[in]     resources  List of names of resources that will be stopped
 *
 * \return Rough estimate of a reasonable time to wait (in seconds) to stop any
 *         one resource in \p resources
 * \note This estimate is very rough, simply the maximum stop timeout of all
 *       given resources and their children, plus a small fudge factor. It does
 *       not account for children that must be stopped in sequence, action
 *       throttling, or any demotions needed. It checks the stop timeout, even
 *       if the resources in question are actually being started.
 */
static guint
wait_time_estimate(pcmk_scheduler_t *scheduler, const GList *resources)
{
    guint max_delay = 0U;

    // Find maximum stop timeout in milliseconds
    for (const GList *item = resources; item != NULL; item = item->next) {
        pcmk_resource_t *rsc = pe_find_resource(scheduler->priv->resources,
                                                (const char *) item->data);
        guint delay = max_rsc_stop_timeout(rsc);

        if (delay > max_delay) {
            pcmk__rsc_trace(rsc,
                            "Wait time is now %s due to %s",
                            pcmk__readable_interval(delay), rsc->id);
            max_delay = delay;
        }
    }

    return pcmk__timeout_ms2s(max_delay) + 5;
}

#define waiting_for_starts(d, r, h) ((d != NULL) || \
                                    (!resource_is_running_on((r), (h))))

/*!
 * \internal
 * \brief Restart a resource (on a particular host if requested).
 *
 * \param[in,out] out                 Output object
 * \param[in,out] rsc                 The resource to restart
 * \param[in]     node                Node to restart resource on (NULL for all)
 * \param[in]     move_lifetime       If not NULL, how long constraint should
 *                                    remain in effect (as ISO 8601 string)
 * \param[in]     timeout_ms          Consider failed if actions do not complete
 *                                    in this time (specified in milliseconds,
 *                                    but a two-second granularity is actually
 *                                    used; if 0, it will be calculated based on
 *                                    the resource timeout)
 * \param[in,out] cib                 Connection to the CIB manager
 * \param[in]     promoted_role_only  If true, limit to promoted instances
 * \param[in]     force               If true, apply only to requested instance
 *                                    if part of a collective resource
 *
 * \return Standard Pacemaker return code (exits on certain failures)
 */
int
cli_resource_restart(pcmk__output_t *out, pcmk_resource_t *rsc,
                     const pcmk_node_t *node, const char *move_lifetime,
                     guint timeout_ms, cib_t *cib, gboolean promoted_role_only,
                     gboolean force)
{
    int rc = pcmk_rc_ok;
    int lpc = 0;
    int before = 0;
    guint step_timeout_s = 0;

    /* @TODO Due to this sleep interval, a timeout <2s will cause problems and
     * should be rejected
     */
    guint sleep_interval = 2U;
    guint timeout = pcmk__timeout_ms2s(timeout_ms);

    bool stop_via_ban = false;
    char *rsc_id = NULL;
    char *lookup_id = NULL;
    char *orig_target_role = NULL;
    xmlNode *cib_xml_orig = NULL;

    GList *list_delta = NULL;
    GList *target_active = NULL;
    GList *current_active = NULL;
    GList *restart_target_active = NULL;

    pcmk_scheduler_t *scheduler = NULL;
    pcmk_resource_t *parent = uber_parent(rsc);

    bool running = false;
    const char *id = pcmk__s(rsc->priv->history_id, rsc->id);
    const char *host = node ? node->priv->name : NULL;

    /* If the implicit resource or primitive resource of a bundle is given, operate on the
     * bundle itself instead.
     */
    if (pcmk__is_bundled(rsc)) {
        rsc = parent->priv->parent;
    }

    running = resource_is_running_on(rsc, host);

    if (pcmk__is_clone(parent) && !running) {
        if (pcmk__is_unique_clone(parent)) {
            lookup_id = strdup(rsc->id);
        } else {
            lookup_id = clone_strip(rsc->id);
        }

        rsc = parent->priv->fns->find_rsc(parent, lookup_id, node,
                                          pcmk_rsc_match_basename
                                          |pcmk_rsc_match_current_node);
        free(lookup_id);
        running = resource_is_running_on(rsc, host);
    }

    if (!running) {
        if (host) {
            out->err(out, "%s is not running on %s and so cannot be restarted", id, host);
        } else {
            out->err(out, "%s is not running anywhere and so cannot be restarted", id);
        }
        return ENXIO;
    }

    if (!pcmk_is_set(rsc->flags, pcmk__rsc_managed)) {
        out->err(out, "Unmanaged resources cannot be restarted.");
        return EAGAIN;
    }

    rsc_id = strdup(rsc->id);

    if (pcmk__is_unique_clone(parent)) {
        lookup_id = strdup(rsc->id);
    } else {
        lookup_id = clone_strip(rsc->id);
    }

    if (host) {
        if (pcmk__is_clone(rsc) || pe_bundle_replicas(rsc)) {
            stop_via_ban = true;
        } else if (pcmk__is_clone(parent)) {
            stop_via_ban = true;
            free(lookup_id);
            lookup_id = strdup(parent->id);
        }
    }

    /*
      grab full cib
      determine originally active resources
      disable or ban
      poll cib and watch for affected resources to get stopped
      without --timeout, calculate the stop timeout for each step and wait for that
      if we hit --timeout or the service timeout, re-enable or un-ban, report failure and indicate which resources we couldn't take down
      if everything stopped, re-enable or un-ban
      poll cib and watch for affected resources to get started
      without --timeout, calculate the start timeout for each step and wait for that
      if we hit --timeout or the service timeout, report (different) failure and indicate which resources we couldn't bring back up
      report success

      Optimizations:
      - use constraints to determine ordered list of affected resources
      - Allow a --no-deps option (aka. --force-restart)
    */

    scheduler = pcmk_new_scheduler();
    if (scheduler == NULL) {
        rc = errno;
        out->err(out, "Could not allocate scheduler data: %s", pcmk_rc_str(rc));
        goto done;
    }

    scheduler->priv->out = out;
    rc = update_dataset(cib, scheduler, &cib_xml_orig, false);

    if(rc != pcmk_rc_ok) {
        out->err(out, "Could not get new resource list: %s (%d)", pcmk_rc_str(rc), rc);
        goto done;
    }

    restart_target_active = get_active_resources(host,
                                                 scheduler->priv->resources);
    current_active = get_active_resources(host, scheduler->priv->resources);

    dump_list(current_active, "Origin");

    if (stop_via_ban) {
        /* Stop the clone or bundle instance by banning it from the host */
        out->quiet = true;
        rc = cli_resource_ban(out, lookup_id, host, move_lifetime, cib,
                              promoted_role_only, PCMK_ROLE_PROMOTED);
    } else {
        xmlNode *xml_search = NULL;

        /* Stop the resource by setting PCMK_META_TARGET_ROLE to Stopped.
         * Remember any existing PCMK_META_TARGET_ROLE so we can restore it
         * later (though it only makes any difference if it's Unpromoted).
         */

        rc = find_resource_attr(out, cib, PCMK_XA_VALUE, lookup_id, NULL, NULL, NULL,
                                PCMK_META_TARGET_ROLE, &xml_search);

        if (rc == pcmk_rc_ok) {
            orig_target_role = crm_element_value_copy(xml_search, PCMK_XA_VALUE);
        }

        pcmk__xml_free(xml_search);

        rc = cli_resource_update_attribute(rsc, rsc_id, NULL,
                                           PCMK_XE_META_ATTRIBUTES, NULL,
                                           PCMK_META_TARGET_ROLE,
                                           PCMK_ACTION_STOPPED, FALSE, cib,
                                           cib_xml_orig, force);
    }
    if(rc != pcmk_rc_ok) {
        out->err(out, "Could not set " PCMK_META_TARGET_ROLE " for %s: %s (%d)",
                 rsc_id, pcmk_rc_str(rc), rc);
        if (current_active != NULL) {
            g_list_free_full(current_active, free);
            current_active = NULL;
        }
        if (restart_target_active != NULL) {
            g_list_free_full(restart_target_active, free);
            restart_target_active = NULL;
        }
        goto done;
    }

    rc = update_dataset(cib, scheduler, &cib_xml_orig, true);
    if(rc != pcmk_rc_ok) {
        out->err(out, "Could not determine which resources would be stopped");
        goto failure;
    }

    target_active = get_active_resources(host, scheduler->priv->resources);
    dump_list(target_active, "Target");

    list_delta = pcmk__subtract_lists(current_active, target_active, (GCompareFunc) strcmp);
    out->info(out, "Waiting for %d resources to stop:", g_list_length(list_delta));
    display_list(out, list_delta, " * ");

    step_timeout_s = timeout / sleep_interval;
    while (list_delta != NULL) {
        before = g_list_length(list_delta);
        if(timeout_ms == 0) {
            step_timeout_s = wait_time_estimate(scheduler, list_delta)
                             / sleep_interval;
        }

        /* We probably don't need the entire step timeout */
        for(lpc = 0; (lpc < step_timeout_s) && (list_delta != NULL); lpc++) {
            sleep(sleep_interval);
            if(timeout) {
                timeout -= sleep_interval;
                crm_trace("%us remaining", timeout);
            }
            rc = update_dataset(cib, scheduler, &cib_xml_orig, false);
            if(rc != pcmk_rc_ok) {
                out->err(out, "Could not determine which resources were stopped");
                goto failure;
            }

            if (current_active != NULL) {
                g_list_free_full(current_active, free);
            }
            current_active = get_active_resources(host,
                                                  scheduler->priv->resources);

            g_list_free(list_delta);
            list_delta = pcmk__subtract_lists(current_active, target_active, (GCompareFunc) strcmp);

            dump_list(current_active, "Current");
            dump_list(list_delta, "Delta");
        }

        crm_trace("%d (was %d) resources remaining", g_list_length(list_delta), before);
        if(before == g_list_length(list_delta)) {
            /* aborted during stop phase, print the contents of list_delta */
            out->err(out, "Could not complete shutdown of %s, %d resources remaining", rsc_id, g_list_length(list_delta));
            display_list(out, list_delta, " * ");
            rc = ETIME;
            goto failure;
        }

    }

    if (stop_via_ban) {
        rc = cli_resource_clear(lookup_id, host, NULL, cib, true, force);

    } else if (orig_target_role) {
        rc = cli_resource_update_attribute(rsc, rsc_id, NULL,
                                           PCMK_XE_META_ATTRIBUTES, NULL,
                                           PCMK_META_TARGET_ROLE,
                                           orig_target_role, FALSE, cib,
                                           cib_xml_orig, force);
        free(orig_target_role);
        orig_target_role = NULL;
    } else {
        rc = cli_resource_delete_attribute(rsc, rsc_id, NULL,
                                           PCMK_XE_META_ATTRIBUTES, NULL,
                                           PCMK_META_TARGET_ROLE, cib,
                                           cib_xml_orig, force);
    }

    if(rc != pcmk_rc_ok) {
        out->err(out,
                 "Could not unset " PCMK_META_TARGET_ROLE " for %s: %s (%d)",
                 rsc_id, pcmk_rc_str(rc), rc);
        goto done;
    }

    if (target_active != NULL) {
        g_list_free_full(target_active, free);
    }
    target_active = restart_target_active;

    list_delta = pcmk__subtract_lists(target_active, current_active, (GCompareFunc) strcmp);
    out->info(out, "Waiting for %d resources to start again:", g_list_length(list_delta));
    display_list(out, list_delta, " * ");

    step_timeout_s = timeout / sleep_interval;
    while (waiting_for_starts(list_delta, rsc, host)) {
        before = g_list_length(list_delta);
        if(timeout_ms == 0) {
            step_timeout_s = wait_time_estimate(scheduler, list_delta)
                             / sleep_interval;
        }

        /* We probably don't need the entire step timeout */
        for (lpc = 0; (lpc < step_timeout_s) && waiting_for_starts(list_delta, rsc, host); lpc++) {

            sleep(sleep_interval);
            if(timeout) {
                timeout -= sleep_interval;
                crm_trace("%ds remaining", timeout);
            }

            rc = update_dataset(cib, scheduler, &cib_xml_orig, false);
            if(rc != pcmk_rc_ok) {
                out->err(out, "Could not determine which resources were started");
                goto failure;
            }

            /* It's OK if dependent resources moved to a different node,
             * so we check active resources on all nodes.
             */
            if (current_active != NULL) {
                g_list_free_full(current_active, free);
            }
            current_active = get_active_resources(NULL,
                                                  scheduler->priv->resources);

            g_list_free(list_delta);
            list_delta = pcmk__subtract_lists(target_active, current_active, (GCompareFunc) strcmp);
            dump_list(current_active, "Current");
            dump_list(list_delta, "Delta");
        }

        if(before == g_list_length(list_delta)) {
            /* aborted during start phase, print the contents of list_delta */
            out->err(out, "Could not complete restart of %s, %d resources remaining", rsc_id, g_list_length(list_delta));
            display_list(out, list_delta, " * ");
            rc = ETIME;
            goto failure;
        }

    }

    rc = pcmk_rc_ok;
    goto done;

  failure:
    if (stop_via_ban) {
        cli_resource_clear(lookup_id, host, NULL, cib, true, force);
    } else if (orig_target_role) {
        cli_resource_update_attribute(rsc, rsc_id, NULL,
                                      PCMK_XE_META_ATTRIBUTES, NULL,
                                      PCMK_META_TARGET_ROLE, orig_target_role,
                                      FALSE, cib, cib_xml_orig, force);
        free(orig_target_role);
    } else {
        cli_resource_delete_attribute(rsc, rsc_id, NULL,
                                      PCMK_XE_META_ATTRIBUTES, NULL,
                                      PCMK_META_TARGET_ROLE, cib, cib_xml_orig,
                                      force);
    }

done:
    if (list_delta != NULL) {
        g_list_free(list_delta);
    }
    if (current_active != NULL) {
        g_list_free_full(current_active, free);
    }
    if (target_active != NULL && (target_active != restart_target_active)) {
        g_list_free_full(target_active, free);
    }
    if (restart_target_active != NULL) {
        g_list_free_full(restart_target_active, free);
    }
    free(rsc_id);
    free(lookup_id);
    pcmk_free_scheduler(scheduler);
    return rc;
}

static inline bool
action_is_pending(const pcmk_action_t *action)
{
    if (pcmk_any_flags_set(action->flags,
                           pcmk__action_optional|pcmk__action_pseudo)
        || !pcmk_is_set(action->flags, pcmk__action_runnable)
        || pcmk__str_eq(PCMK_ACTION_NOTIFY, action->task, pcmk__str_casei)) {
        return false;
    }
    return true;
}

/*!
 * \internal
 * \brief Check whether any actions in a list are pending
 *
 * \param[in] actions   List of actions to check
 *
 * \return true if any actions in the list are pending, otherwise false
 */
static bool
actions_are_pending(const GList *actions)
{
    for (const GList *action = actions; action != NULL; action = action->next) {
        const pcmk_action_t *a = (const pcmk_action_t *) action->data;

        if (action_is_pending(a)) {
            crm_notice("Waiting for %s (flags=%#.8x)", a->uuid, a->flags);
            return true;
        }
    }
    return false;
}

static void
print_pending_actions(pcmk__output_t *out, GList *actions)
{
    GList *action;

    out->info(out, "Pending actions:");
    for (action = actions; action != NULL; action = action->next) {
        pcmk_action_t *a = (pcmk_action_t *) action->data;

        if (!action_is_pending(a)) {
            continue;
        }

        if (a->node) {
            out->info(out, "\tAction %d: %s\ton %s",
                      a->id, a->uuid, pcmk__node_name(a->node));
        } else {
            out->info(out, "\tAction %d: %s", a->id, a->uuid);
        }
    }
}

/* For --wait, timeout (in seconds) to use if caller doesn't specify one */
#define WAIT_DEFAULT_TIMEOUT_S (60 * 60)

/* For --wait, how long to sleep between cluster state checks */
#define WAIT_SLEEP_S (2)

/*!
 * \internal
 * \brief Wait until all pending cluster actions are complete
 *
 * This waits until either the CIB's transition graph is idle or a timeout is
 * reached.
 *
 * \param[in,out] out          Output object
 * \param[in]     timeout_ms   Consider failed if actions do not complete in
 *                             this time (specified in milliseconds, but
 *                             one-second granularity is actually used; if 0, a
 *                             default will be used)
 * \param[in,out] cib          Connection to the CIB manager
 *
 * \return Standard Pacemaker return code
 */
int
wait_till_stable(pcmk__output_t *out, guint timeout_ms, cib_t * cib)
{
    pcmk_scheduler_t *scheduler = NULL;
    xmlXPathObjectPtr search;
    int rc = pcmk_rc_ok;
    bool pending_unknown_state_resources;
    time_t expire_time = time(NULL);
    time_t time_diff;
    bool printed_version_warning = out->is_quiet(out); // i.e. don't print if quiet
    char *xpath = NULL;

    if (timeout_ms == 0) {
        expire_time += WAIT_DEFAULT_TIMEOUT_S;
    } else {
        expire_time += pcmk__timeout_ms2s(timeout_ms + 999);
    }

    scheduler = pcmk_new_scheduler();
    if (scheduler == NULL) {
        return ENOMEM;
    }

    xpath = crm_strdup_printf("/" PCMK_XE_CIB "/" PCMK_XE_STATUS
                              "/" PCMK__XE_NODE_STATE "/" PCMK__XE_LRM
                              "/" PCMK__XE_LRM_RESOURCES
                              "/" PCMK__XE_LRM_RESOURCE
                              "/" PCMK__XE_LRM_RSC_OP
                              "[@" PCMK__XA_RC_CODE "='%d']",
                              PCMK_OCF_UNKNOWN);
    do {
        /* Abort if timeout is reached */
        time_diff = expire_time - time(NULL);
        if (time_diff <= 0) {
            print_pending_actions(out, scheduler->priv->actions);
            rc = ETIME;
            break;
        }

        crm_info("Waiting up to %lld seconds for cluster actions to complete",
                 (long long) time_diff);

        if (rc == pcmk_rc_ok) { /* this avoids sleep on first loop iteration */
            sleep(WAIT_SLEEP_S);
        }

        /* Get latest transition graph */
        pcmk_reset_scheduler(scheduler);
        rc = update_scheduler_input(out, scheduler, cib, NULL);
        if (rc != pcmk_rc_ok) {
            break;
        }
        pcmk__schedule_actions(scheduler->input, pcmk__sched_no_counts,
                               scheduler);

        if (!printed_version_warning) {
            /* If the DC has a different version than the local node, the two
             * could come to different conclusions about what actions need to be
             * done. Warn the user in this case.
             *
             * @TODO A possible long-term solution would be to reimplement the
             * wait as a new controller operation that would be forwarded to the
             * DC. However, that would have potential problems of its own.
             */
            const char *dc_version = NULL;

            dc_version = g_hash_table_lookup(scheduler->priv->options,
                                             PCMK_OPT_DC_VERSION);
            if (!pcmk__str_eq(dc_version, PACEMAKER_VERSION "-" BUILD_VERSION, pcmk__str_casei)) {
                out->info(out, "warning: wait option may not work properly in "
                          "mixed-version cluster");
                printed_version_warning = true;
            }
        }

        search = xpath_search(scheduler->input, xpath);
        pending_unknown_state_resources = (numXpathResults(search) > 0);
        freeXpathObject(search);
    } while (actions_are_pending(scheduler->priv->actions)
             || pending_unknown_state_resources);

    pcmk_free_scheduler(scheduler);
    free(xpath);
    return rc;
}

static const char *
get_action(const char *rsc_action) {
    const char *action = NULL;

    if (pcmk__str_eq(rsc_action, "validate", pcmk__str_casei)) {
        action = PCMK_ACTION_VALIDATE_ALL;

    } else if (pcmk__str_eq(rsc_action, "force-check", pcmk__str_casei)) {
        action = PCMK_ACTION_MONITOR;

    } else if (pcmk__strcase_any_of(rsc_action, "force-start", "force-stop",
                                    "force-demote", "force-promote", NULL)) {
        action = rsc_action+6;
    } else {
        action = rsc_action;
    }

    return action;
}

/*!
 * \brief Set up environment variables as expected by resource agents
 *
 * When the cluster executes resource agents, it adds certain environment
 * variables (directly or via resource meta-attributes) expected by some
 * resource agents. Add the essential ones that many resource agents expect, so
 * the behavior is the same for command-line execution.
 *
 * \param[in,out] params       Resource parameters that will be passed to agent
 * \param[in]     timeout_ms   Action timeout (in milliseconds)
 * \param[in]     check_level  OCF check level
 * \param[in]     verbosity    Verbosity level
 */
static void
set_agent_environment(GHashTable *params, guint timeout_ms, int check_level,
                      int verbosity)
{
    g_hash_table_insert(params, crm_meta_name(PCMK_META_TIMEOUT),
                        crm_strdup_printf("%u", timeout_ms));

    pcmk__insert_dup(params, PCMK_XA_CRM_FEATURE_SET, CRM_FEATURE_SET);

    if (check_level >= 0) {
        char *level = crm_strdup_printf("%d", check_level);

        setenv("OCF_CHECK_LEVEL", level, 1);
        free(level);
    }

    pcmk__set_env_option(PCMK__ENV_DEBUG, ((verbosity > 0)? "1" : "0"), true);
    if (verbosity > 1) {
        setenv("OCF_TRACE_RA", "1", 1);
    }

    /* A resource agent using the standard ocf-shellfuncs library will not print
     * messages to stderr if it doesn't have a controlling terminal (e.g. if
     * crm_resource is called via script or ssh). This forces it to do so.
     */
    setenv("OCF_TRACE_FILE", "/dev/stderr", 0);
}

/*!
 * \internal
 * \brief Apply command-line overrides to resource parameters
 *
 * \param[in,out] params     Parameters to be passed to agent
 * \param[in]     overrides  Parameters to override (or NULL if none)
 */
static void
apply_overrides(GHashTable *params, GHashTable *overrides)
{
    if (overrides != NULL) {
        GHashTableIter iter;
        char *name = NULL;
        char *value = NULL;

        g_hash_table_iter_init(&iter, overrides);
        while (g_hash_table_iter_next(&iter, (gpointer *) &name,
                                      (gpointer *) &value)) {
            pcmk__insert_dup(params, name, value);
        }
    }
}

crm_exit_t
cli_resource_execute_from_params(pcmk__output_t *out, const char *rsc_name,
                                 const char *rsc_class, const char *rsc_prov,
                                 const char *rsc_type, const char *rsc_action,
                                 GHashTable *params, GHashTable *override_hash,
                                 guint timeout_ms, int resource_verbose,
                                 gboolean force, int check_level)
{
    const char *class = rsc_class;
    const char *action = get_action(rsc_action);
    crm_exit_t exit_code = CRM_EX_OK;
    svc_action_t *op = NULL;

    // If no timeout was provided, use the same default as the cluster
    if (timeout_ms == 0U) {
        timeout_ms = PCMK_DEFAULT_ACTION_TIMEOUT_MS;
    }

    set_agent_environment(params, timeout_ms, check_level, resource_verbose);
    apply_overrides(params, override_hash);

    op = services__create_resource_action(rsc_name? rsc_name : "test",
                                          rsc_class, rsc_prov, rsc_type, action,
                                          0, QB_MIN(timeout_ms, INT_MAX),
                                          params, 0);
    if (op == NULL) {
        out->err(out, "Could not execute %s using %s%s%s:%s: %s",
                 action, rsc_class, (rsc_prov? ":" : ""),
                 (rsc_prov? rsc_prov : ""), rsc_type, strerror(ENOMEM));
        g_hash_table_destroy(params);
        return CRM_EX_OSERR;
    }

#if PCMK__ENABLE_SERVICE
    if (pcmk__str_eq(rsc_class, PCMK_RESOURCE_CLASS_SERVICE, pcmk__str_casei)) {
        class = resources_find_service_class(rsc_type);
    }
#endif

    if (!pcmk_is_set(pcmk_get_ra_caps(class), pcmk_ra_cap_cli_exec)) {
        services__format_result(op, CRM_EX_UNIMPLEMENT_FEATURE, PCMK_EXEC_ERROR,
                                "Manual execution of the %s standard is "
                                "unsupported", pcmk__s(class, "unspecified"));
    }

    if (op->rc != PCMK_OCF_UNKNOWN) {
        exit_code = op->rc;
        goto done;
    }

    services_action_sync(op);

    // Map results to OCF codes for consistent reporting to user
    {
        enum ocf_exitcode ocf_code = services_result2ocf(class, action, op->rc);

        // Cast variable instead of function return to keep compilers happy
        exit_code = (crm_exit_t) ocf_code;
    }

done:
    out->message(out, "resource-agent-action", resource_verbose, rsc_class,
                 rsc_prov, rsc_type, rsc_name, rsc_action, override_hash,
                 exit_code, op->status, services__exit_reason(op),
                 op->stdout_data, op->stderr_data);
    services_action_free(op);
    return exit_code;
}

/*!
 * \internal
 * \brief Get the timeout the cluster would use for an action
 *
 * \param[in] rsc     Resource that action is for
 * \param[in] action  Name of action
 */
static guint
get_action_timeout(pcmk_resource_t *rsc, const char *action)
{
    long long timeout_ms = -1LL;
    xmlNode *op = pcmk__find_action_config(rsc, action, 0, true);
    GHashTable *meta = pcmk__unpack_action_meta(rsc, NULL, action, 0, op);

    if ((pcmk__scan_ll(g_hash_table_lookup(meta, PCMK_META_TIMEOUT),
                       &timeout_ms, -1LL) != pcmk_rc_ok)
        || (timeout_ms <= 0LL)) {
        timeout_ms = PCMK_DEFAULT_ACTION_TIMEOUT_MS;
    }
    g_hash_table_destroy(meta);
    return (guint) QB_MIN(timeout_ms, UINT_MAX);
}

crm_exit_t
cli_resource_execute(pcmk_resource_t *rsc, const char *requested_name,
                     const char *rsc_action, GHashTable *override_hash,
                     guint timeout_ms, cib_t *cib, pcmk_scheduler_t *scheduler,
                     int resource_verbose, gboolean force, int check_level)
{
    pcmk__output_t *out = scheduler->priv->out;
    crm_exit_t exit_code = CRM_EX_OK;
    const char *rid = requested_name;
    const char *rtype = NULL;
    const char *rprov = NULL;
    const char *rclass = NULL;
    GHashTable *params = NULL;

    if (pcmk__strcase_any_of(rsc_action, "force-start", "force-demote",
                                    "force-promote", NULL)) {
        if (pcmk__is_clone(rsc)) {
            GList *nodes = cli_resource_search(rsc, requested_name, scheduler);
            if(nodes != NULL && force == FALSE) {
                out->err(out, "It is not safe to %s %s here: the cluster claims it is already active",
                         rsc_action, rsc->id);
                out->err(out,
                         "Try setting "
                         PCMK_META_TARGET_ROLE "=" PCMK_ROLE_STOPPED
                         " first or specifying the force option");
                return CRM_EX_UNSAFE;
            }

            g_list_free_full(nodes, free);
        }
    }

    if (pcmk__is_clone(rsc)) {
        /* Grab the first child resource in the hope it's not a group */
        rsc = rsc->priv->children->data;
    }

    if (pcmk__is_group(rsc)) {
        out->err(out, "Sorry, the %s option doesn't support group resources", rsc_action);
        return CRM_EX_UNIMPLEMENT_FEATURE;
    } else if (pcmk__is_bundled(rsc)) {
        out->err(out, "Sorry, the %s option doesn't support bundled resources", rsc_action);
        return CRM_EX_UNIMPLEMENT_FEATURE;
    }

    rclass = crm_element_value(rsc->priv->xml, PCMK_XA_CLASS);
    rprov = crm_element_value(rsc->priv->xml, PCMK_XA_PROVIDER);
    rtype = crm_element_value(rsc->priv->xml, PCMK_XA_TYPE);

    params = generate_resource_params(rsc, NULL /* @TODO use local node */,
                                      scheduler);

    if (timeout_ms == 0U) {
        timeout_ms = get_action_timeout(rsc, get_action(rsc_action));
    }

    if (!pcmk__is_anonymous_clone(rsc->priv->parent)) {
        rid = rsc->id;
    }

    exit_code = cli_resource_execute_from_params(out, rid, rclass, rprov, rtype, rsc_action,
                                                 params, override_hash, timeout_ms,
                                                 resource_verbose, force, check_level);
    return exit_code;
}

// \return Standard Pacemaker return code
int
cli_resource_move(const pcmk_resource_t *rsc, const char *rsc_id,
                  const char *host_name, const char *move_lifetime, cib_t *cib,
                  pcmk_scheduler_t *scheduler, gboolean promoted_role_only,
                  gboolean force)
{
    pcmk__output_t *out = scheduler->priv->out;
    int rc = pcmk_rc_ok;
    unsigned int count = 0;
    pcmk_node_t *current = NULL;
    pcmk_node_t *dest = pcmk_find_node(scheduler, host_name);
    bool cur_is_dest = false;

    if (dest == NULL) {
        return pcmk_rc_node_unknown;
    }

    if (promoted_role_only
        && !pcmk_is_set(rsc->flags, pcmk__rsc_promotable)) {

        const pcmk_resource_t *p = pe__const_top_resource(rsc, false);

        if (pcmk_is_set(p->flags, pcmk__rsc_promotable)) {
            out->info(out, "Using parent '%s' for move instead of '%s'.", rsc->id, rsc_id);
            rsc_id = p->id;
            rsc = p;

        } else {
            out->info(out, "Ignoring --promoted option: %s is not promotable",
                      rsc_id);
            promoted_role_only = FALSE;
        }
    }

    current = pe__find_active_requires(rsc, &count);

    if (pcmk_is_set(rsc->flags, pcmk__rsc_promotable)) {
        unsigned int promoted_count = 0;
        pcmk_node_t *promoted_node = NULL;

        for (const GList *iter = rsc->priv->children;
             iter != NULL; iter = iter->next) {

            const pcmk_resource_t *child = (const pcmk_resource_t *) iter->data;
            enum rsc_role_e child_role = child->priv->fns->state(child, TRUE);

            if (child_role == pcmk_role_promoted) {
                rsc = child;
                promoted_node = pcmk__current_node(child);
                promoted_count++;
            }
        }
        if (promoted_role_only || (promoted_count != 0)) {
            count = promoted_count;
            current = promoted_node;
        }

    }

    if (count > 1) {
        if (pcmk__is_clone(rsc)) {
            current = NULL;
        } else {
            return pcmk_rc_multiple;
        }
    }

    if (pcmk__same_node(current, dest)) {
        cur_is_dest = true;
        if (force) {
            crm_info("%s is already %s on %s, reinforcing placement with location constraint.",
                     rsc_id, promoted_role_only?"promoted":"active",
                     pcmk__node_name(dest));
        } else {
            return pcmk_rc_already;
        }
    }

    /* @TODO The constraint changes in the following commands should done
     * atomically in a single CIB transaction, to avoid the possibility of
     * multiple moves
     */

    /* Clear any previous prefer constraints across all nodes. */
    cli_resource_clear(rsc_id, NULL, scheduler->nodes, cib, false, force);

    /* Clear any previous ban constraints on 'dest'. */
    cli_resource_clear(rsc_id, dest->priv->name, scheduler->nodes, cib, true,
                       force);

    /* Record an explicit preference for 'dest' */
    rc = cli_resource_prefer(out, rsc_id, dest->priv->name, move_lifetime,
                             cib, promoted_role_only, PCMK_ROLE_PROMOTED);

    crm_trace("%s%s now prefers %s%s",
              rsc->id, (promoted_role_only? " (promoted)" : ""),
              pcmk__node_name(dest), force?"(forced)":"");

    /* only ban the previous location if current location != destination location.
     * it is possible to use -M to enforce a location without regard of where the
     * resource is currently located */
    if (force && !cur_is_dest) {
        /* Ban the original location if possible */
        if(current) {
            (void)cli_resource_ban(out, rsc_id, current->priv->name,
                                   move_lifetime, cib, promoted_role_only,
                                   PCMK_ROLE_PROMOTED);
        } else if(count > 1) {
            out->info(out, "Resource '%s' is currently %s in %d locations. "
                      "One may now move to %s",
                      rsc_id, (promoted_role_only? "promoted" : "active"),
                      count, pcmk__node_name(dest));
            out->info(out, "To prevent '%s' from being %s at a specific location, "
                      "specify a node.",
                      rsc_id, (promoted_role_only? "promoted" : "active"));

        } else {
            crm_trace("Not banning %s from its current location: not active", rsc_id);
        }
    }

    return rc;
}

/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm_resource.h>
#include <crm/common/ipc_controld.h>
#include <crm/common/lists_internal.h>
#include <crm/services_internal.h>

resource_checks_t *
cli_check_resource(pe_resource_t *rsc, char *role_s, char *managed)
{
    pe_resource_t *parent = uber_parent(rsc);
    resource_checks_t *rc = calloc(1, sizeof(resource_checks_t));

    if (role_s) {
        enum rsc_role_e role = text2role(role_s);

        if (role == RSC_ROLE_STOPPED) {
            rc->flags |= rsc_remain_stopped;
        } else if (pcmk_is_set(parent->flags, pe_rsc_promotable) &&
                   (role == RSC_ROLE_UNPROMOTED)) {
            rc->flags |= rsc_unpromotable;
        }
    }

    if (managed && !crm_is_true(managed)) {
        rc->flags |= rsc_unmanaged;
    }

    if (rsc->lock_node) {
        rc->lock_node = rsc->lock_node->details->uname;
    }

    rc->rsc = rsc;
    return rc;
}

static GList *
build_node_info_list(pe_resource_t *rsc)
{
    GList *retval = NULL;

    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        pe_resource_t *child = (pe_resource_t *) iter->data;

        for (GList *iter2 = child->running_on; iter2 != NULL; iter2 = iter2->next) {
            pe_node_t *node = (pe_node_t *) iter2->data;
            node_info_t *ni = calloc(1, sizeof(node_info_t));
            ni->node_name = node->details->uname;
            ni->promoted = pcmk_is_set(rsc->flags, pe_rsc_promotable) &&
                           child->fns->state(child, TRUE) == RSC_ROLE_PROMOTED;

            retval = g_list_prepend(retval, ni);
        }
    }

    return retval;
}

GList *
cli_resource_search(pe_resource_t *rsc, const char *requested_name,
                    pe_working_set_t *data_set)
{
    GList *retval = NULL;
    pe_resource_t *parent = uber_parent(rsc);

    if (pe_rsc_is_clone(rsc)) {
        retval = build_node_info_list(rsc);

    /* The anonymous clone children's common ID is supplied */
    } else if (pe_rsc_is_clone(parent)
               && !pcmk_is_set(rsc->flags, pe_rsc_unique)
               && rsc->clone_name
               && pcmk__str_eq(requested_name, rsc->clone_name, pcmk__str_casei)
               && !pcmk__str_eq(requested_name, rsc->id, pcmk__str_casei)) {

        retval = build_node_info_list(parent);

    } else if (rsc->running_on != NULL) {
        for (GList *iter = rsc->running_on; iter != NULL; iter = iter->next) {
            pe_node_t *node = (pe_node_t *) iter->data;
            node_info_t *ni = calloc(1, sizeof(node_info_t));
            ni->node_name = node->details->uname;
            ni->promoted = (rsc->fns->state(rsc, TRUE) == RSC_ROLE_PROMOTED);

            retval = g_list_prepend(retval, ni);
        }
    }

    return retval;
}

#define XPATH_MAX 1024

// \return Standard Pacemaker return code
static int
find_resource_attr(pcmk__output_t *out, cib_t * the_cib, const char *attr,
                   const char *rsc, const char *attr_set_type, const char *set_name,
                   const char *attr_id, const char *attr_name, char **value)
{
    int offset = 0;
    int rc = pcmk_rc_ok;
    xmlNode *xml_search = NULL;
    char *xpath_string = NULL;
    const char *xpath_base = NULL;

    if(value) {
        *value = NULL;
    }

    if(the_cib == NULL) {
        return ENOTCONN;
    }

    xpath_base = pcmk_cib_xpath_for(XML_CIB_TAG_RESOURCES);
    if (xpath_base == NULL) {
        crm_err(XML_CIB_TAG_RESOURCES " CIB element not known (bug?)");
        return ENOMSG;
    }

    xpath_string = calloc(1, XPATH_MAX);
    offset += snprintf(xpath_string + offset, XPATH_MAX - offset, "%s",
                       xpath_base);

    offset += snprintf(xpath_string + offset, XPATH_MAX - offset, "//*[@id=\"%s\"]", rsc);

    if (attr_set_type) {
        offset += snprintf(xpath_string + offset, XPATH_MAX - offset, "/%s", attr_set_type);
        if (set_name) {
            offset += snprintf(xpath_string + offset, XPATH_MAX - offset, "[@id=\"%s\"]", set_name);
        }
    }

    offset += snprintf(xpath_string + offset, XPATH_MAX - offset, "//nvpair[");
    if (attr_id) {
        offset += snprintf(xpath_string + offset, XPATH_MAX - offset, "@id=\"%s\"", attr_id);
    }

    if (attr_name) {
        if (attr_id) {
            offset += snprintf(xpath_string + offset, XPATH_MAX - offset, " and ");
        }
        offset += snprintf(xpath_string + offset, XPATH_MAX - offset, "@name=\"%s\"", attr_name);
    }
    offset += snprintf(xpath_string + offset, XPATH_MAX - offset, "]");
    CRM_LOG_ASSERT(offset > 0);

    rc = the_cib->cmds->query(the_cib, xpath_string, &xml_search,
                              cib_sync_call | cib_scope_local | cib_xpath);
    rc = pcmk_legacy2rc(rc);

    if (rc != pcmk_rc_ok) {
        goto done;
    }

    crm_log_xml_debug(xml_search, "Match");
    if (xml_has_children(xml_search)) {
        xmlNode *child = NULL;

        rc = ENOTUNIQ;
        out->info(out, "Multiple attributes match name=%s", attr_name);

        for (child = pcmk__xml_first_child(xml_search); child != NULL;
             child = pcmk__xml_next(child)) {
            out->info(out, "  Value: %s \t(id=%s)",
                      crm_element_value(child, XML_NVPAIR_ATTR_VALUE), ID(child));
        }

        out->spacer(out);

    } else if(value) {
        pcmk__str_update(value, crm_element_value(xml_search, attr));
    }

  done:
    free(xpath_string);
    free_xml(xml_search);
    return rc;
}

/* PRIVATE. Use the find_matching_attr_resources instead. */
static void
find_matching_attr_resources_recursive(pcmk__output_t *out, GList/* <pe_resource_t*> */ ** result,
                                       pe_resource_t * rsc, const char * rsc_id,
                                       const char * attr_set, const char * attr_set_type,
                                       const char * attr_id, const char * attr_name,
                                       cib_t * cib, const char * cmd, int depth)
{
    int rc = pcmk_rc_ok;
    char *lookup_id = clone_strip(rsc->id);
    char *local_attr_id = NULL;

    /* visit the children */
    for(GList *gIter = rsc->children; gIter; gIter = gIter->next) {
        find_matching_attr_resources_recursive(out, result, (pe_resource_t*)gIter->data,
                                               rsc_id, attr_set, attr_set_type,
                                               attr_id, attr_name, cib, cmd, depth+1);
        /* do it only once for clones */
        if(pe_clone == rsc->variant) {
            break;
        }
    }

    rc = find_resource_attr(out, cib, XML_ATTR_ID, lookup_id, attr_set_type,
                            attr_set, attr_id, attr_name, &local_attr_id);
    /* Post-order traversal. 
     * The root is always on the list and it is the last item. */
    if((0 == depth) || (pcmk_rc_ok == rc)) {
        /* push the head */
        *result = g_list_append(*result, rsc);
    }

    free(local_attr_id);
    free(lookup_id);
}


/* The result is a linearized pre-ordered tree of resources. */
static GList/*<pe_resource_t*>*/ *
find_matching_attr_resources(pcmk__output_t *out, pe_resource_t * rsc,
                             const char * rsc_id, const char * attr_set,
                             const char * attr_set_type, const char * attr_id,
                             const char * attr_name, cib_t * cib, const char * cmd,
                             gboolean force)
{
    int rc = pcmk_rc_ok;
    char *lookup_id = NULL;
    char *local_attr_id = NULL;
    GList * result = NULL;
    /* If --force is used, update only the requested resource (clone or primitive).
     * Otherwise, if the primitive has the attribute, use that.
     * Otherwise use the clone. */
    if(force == TRUE) {
        return g_list_append(result, rsc);
    }
    if(rsc->parent && pe_clone == rsc->parent->variant) {
        int rc = pcmk_rc_ok;
        char *local_attr_id = NULL;
        rc = find_resource_attr(out, cib, XML_ATTR_ID, rsc_id, attr_set_type,
                                attr_set, attr_id, attr_name, &local_attr_id);
        free(local_attr_id);

        if(rc != pcmk_rc_ok) {
            rsc = rsc->parent;
            out->info(out, "Performing %s of '%s' on '%s', the parent of '%s'",
                      cmd, attr_name, rsc->id, rsc_id);
        }
        return g_list_append(result, rsc);
    } else if(rsc->parent == NULL && rsc->children && pe_clone == rsc->variant) {
        pe_resource_t *child = rsc->children->data;

        if(child->variant == pe_native) {
            lookup_id = clone_strip(child->id); /* Could be a cloned group! */
            rc = find_resource_attr(out, cib, XML_ATTR_ID, lookup_id, attr_set_type,
                                    attr_set, attr_id, attr_name, &local_attr_id);

            if(rc == pcmk_rc_ok) {
                rsc = child;
                out->info(out, "A value for '%s' already exists in child '%s', performing %s on that instead of '%s'",
                          attr_name, lookup_id, cmd, rsc_id);
            }

            free(local_attr_id);
            free(lookup_id);
        }
        return g_list_append(result, rsc);
    }
    /* If the resource is a group ==> children inherit the attribute if defined. */
    find_matching_attr_resources_recursive(out, &result, rsc, rsc_id, attr_set,
                                           attr_set_type, attr_id, attr_name,
                                           cib, cmd, 0);
    return result;
}

// \return Standard Pacemaker return code
int
cli_resource_update_attribute(pe_resource_t *rsc, const char *requested_name,
                              const char *attr_set, const char *attr_set_type,
                              const char *attr_id, const char *attr_name,
                              const char *attr_value, gboolean recursive,
                              cib_t *cib, int cib_options,
                              pe_working_set_t *data_set, gboolean force)
{
    pcmk__output_t *out = data_set->priv;
    int rc = pcmk_rc_ok;
    static bool need_init = true;

    char *local_attr_id = NULL;
    char *local_attr_set = NULL;

    GList/*<pe_resource_t*>*/ *resources = NULL;
    const char *common_attr_id = attr_id;

    if (attr_id == NULL && force == FALSE) {
        find_resource_attr (out, cib, XML_ATTR_ID, uber_parent(rsc)->id, NULL,
                            NULL, NULL, attr_name, NULL);
    }

    if (pcmk__str_eq(attr_set_type, XML_TAG_ATTR_SETS, pcmk__str_casei)) {
        if (force == FALSE) {
            rc = find_resource_attr(out, cib, XML_ATTR_ID, uber_parent(rsc)->id,
                                    XML_TAG_META_SETS, attr_set, attr_id,
                                    attr_name, &local_attr_id);
            if (rc == pcmk_rc_ok && !out->is_quiet(out)) {
                out->err(out, "WARNING: There is already a meta attribute for '%s' called '%s' (id=%s)",
                         uber_parent(rsc)->id, attr_name, local_attr_id);
                out->err(out, "         Delete '%s' first or use the force option to override",
                         local_attr_id);
            }
            free(local_attr_id);
            if (rc == pcmk_rc_ok) {
                return ENOTUNIQ;
            }
        }
        resources = g_list_append(resources, rsc);

    } else {
        resources = find_matching_attr_resources(out, rsc, requested_name, attr_set, attr_set_type,
                                                 attr_id, attr_name, cib, "update", force);
    }

    /* If either attr_set or attr_id is specified,
     * one clearly intends to modify a single resource.
     * It is the last item on the resource list.*/
    for(GList *gIter = (attr_set||attr_id) ? g_list_last(resources) : resources
            ; gIter; gIter = gIter->next) {
        char *lookup_id = NULL;

        xmlNode *xml_top = NULL;
        xmlNode *xml_obj = NULL;
        local_attr_id = NULL;
        local_attr_set = NULL;

        rsc = (pe_resource_t*)gIter->data;
        attr_id = common_attr_id;

        lookup_id = clone_strip(rsc->id); /* Could be a cloned group! */
        rc = find_resource_attr(out, cib, XML_ATTR_ID, lookup_id, attr_set_type,
                                attr_set, attr_id, attr_name, &local_attr_id);

        if (rc == pcmk_rc_ok) {
            crm_debug("Found a match for name=%s: id=%s", attr_name, local_attr_id);
            attr_id = local_attr_id;

        } else if (rc != ENXIO) {
            free(lookup_id);
            free(local_attr_id);
            g_list_free(resources);
            return rc;

        } else {
            const char *tag = crm_element_name(rsc->xml);

            if (attr_set == NULL) {
                local_attr_set = crm_strdup_printf("%s-%s", lookup_id,
                                                   attr_set_type);
                attr_set = local_attr_set;
            }
            if (attr_id == NULL) {
                local_attr_id = crm_strdup_printf("%s-%s", attr_set, attr_name);
                attr_id = local_attr_id;
            }

            xml_top = create_xml_node(NULL, tag);
            crm_xml_add(xml_top, XML_ATTR_ID, lookup_id);

            xml_obj = create_xml_node(xml_top, attr_set_type);
            crm_xml_add(xml_obj, XML_ATTR_ID, attr_set);
        }

        xml_obj = crm_create_nvpair_xml(xml_obj, attr_id, attr_name, attr_value);
        if (xml_top == NULL) {
            xml_top = xml_obj;
        }

        crm_log_xml_debug(xml_top, "Update");

        rc = cib->cmds->modify(cib, XML_CIB_TAG_RESOURCES, xml_top, cib_options);
        rc = pcmk_legacy2rc(rc);

        if (rc == pcmk_rc_ok) {
            out->info(out, "Set '%s' option: id=%s%s%s%s%s value=%s", lookup_id, local_attr_id,
                      attr_set ? " set=" : "", attr_set ? attr_set : "",
                      attr_name ? " name=" : "", attr_name ? attr_name : "", attr_value);
        }

        free_xml(xml_top);

        free(lookup_id);
        free(local_attr_id);
        free(local_attr_set);

        if(recursive && pcmk__str_eq(attr_set_type, XML_TAG_META_SETS, pcmk__str_casei)) {
            GList *lpc = NULL;

            if(need_init) {
                need_init = false;
                pcmk__unpack_constraints(data_set);
                pe__clear_resource_flags_on_all(data_set, pe_rsc_allocating);
            }

            crm_debug("Looking for dependencies %p", rsc->rsc_cons_lhs);
            pe__set_resource_flags(rsc, pe_rsc_allocating);
            for (lpc = rsc->rsc_cons_lhs; lpc != NULL; lpc = lpc->next) {
                pcmk__colocation_t *cons = (pcmk__colocation_t *) lpc->data;

                crm_debug("Checking %s %d", cons->id, cons->score);
                if ((cons->score > 0)
                    && !pcmk_is_set(cons->dependent->flags, pe_rsc_allocating)) {
                    /* Don't get into colocation loops */
                    crm_debug("Setting %s=%s for dependent resource %s",
                              attr_name, attr_value, cons->dependent->id);
                    cli_resource_update_attribute(cons->dependent,
                                                  cons->dependent->id, NULL,
                                                  attr_set_type, NULL,
                                                  attr_name, attr_value,
                                                  recursive, cib, cib_options,
                                                  data_set, force);
                }
            }
        }
    }
    g_list_free(resources);
    return rc;
}

// \return Standard Pacemaker return code
int
cli_resource_delete_attribute(pe_resource_t *rsc, const char *requested_name,
                              const char *attr_set, const char *attr_set_type,
                              const char *attr_id, const char *attr_name,
                              cib_t *cib, int cib_options,
                              pe_working_set_t *data_set, gboolean force)
{
    pcmk__output_t *out = data_set->priv;
    int rc = pcmk_rc_ok;
    GList/*<pe_resource_t*>*/ *resources = NULL;

    if (attr_id == NULL && force == FALSE) {
        find_resource_attr(out, cib, XML_ATTR_ID, uber_parent(rsc)->id, NULL,
                           NULL, NULL, attr_name, NULL);
    }

    if(pcmk__str_eq(attr_set_type, XML_TAG_META_SETS, pcmk__str_casei)) {
        resources = find_matching_attr_resources(out, rsc, requested_name, attr_set, attr_set_type,
                                                 attr_id, attr_name, cib, "delete", force);
    } else {
        resources = g_list_append(resources, rsc);
    }

    for(GList *gIter = resources; gIter; gIter = gIter->next) {
        char *lookup_id = NULL;
        xmlNode *xml_obj = NULL;
        char *local_attr_id = NULL;

        rsc = (pe_resource_t*)gIter->data;

        lookup_id = clone_strip(rsc->id);
        rc = find_resource_attr(out, cib, XML_ATTR_ID, lookup_id, attr_set_type,
                                attr_set, attr_id, attr_name, &local_attr_id);

        if (rc == ENXIO) {
            free(lookup_id);
            rc = pcmk_rc_ok;
            continue;

        } else if (rc != pcmk_rc_ok) {
            free(lookup_id);
            g_list_free(resources);
            return rc;
        }

        if (attr_id == NULL) {
            attr_id = local_attr_id;
        }

        xml_obj = crm_create_nvpair_xml(NULL, attr_id, attr_name, NULL);
        crm_log_xml_debug(xml_obj, "Delete");

        CRM_ASSERT(cib);
        rc = cib->cmds->remove(cib, XML_CIB_TAG_RESOURCES, xml_obj, cib_options);
        rc = pcmk_legacy2rc(rc);

        if (rc == pcmk_rc_ok) {
            out->info(out, "Deleted '%s' option: id=%s%s%s%s%s", lookup_id, local_attr_id,
                      attr_set ? " set=" : "", attr_set ? attr_set : "",
                      attr_name ? " name=" : "", attr_name ? attr_name : "");
        }

        free(lookup_id);
        free_xml(xml_obj);
        free(local_attr_id);
    }
    g_list_free(resources);
    return rc;
}

// \return Standard Pacemaker return code
static int
send_lrm_rsc_op(pcmk_ipc_api_t *controld_api, bool do_fail_resource,
                const char *host_uname, const char *rsc_id, pe_working_set_t *data_set)
{
    pcmk__output_t *out = data_set->priv;
    const char *router_node = host_uname;
    const char *rsc_api_id = NULL;
    const char *rsc_long_id = NULL;
    const char *rsc_class = NULL;
    const char *rsc_provider = NULL;
    const char *rsc_type = NULL;
    bool cib_only = false;
    pe_resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);

    if (rsc == NULL) {
        out->err(out, "Resource %s not found", rsc_id);
        return ENXIO;

    } else if (rsc->variant != pe_native) {
        out->err(out, "We can only process primitive resources, not %s", rsc_id);
        return EINVAL;
    }

    rsc_class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    rsc_provider = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER),
    rsc_type = crm_element_value(rsc->xml, XML_ATTR_TYPE);
    if ((rsc_class == NULL) || (rsc_type == NULL)) {
        out->err(out, "Resource %s does not have a class and type", rsc_id);
        return EINVAL;
    }

    {
        pe_node_t *node = pe_find_node(data_set->nodes, host_uname);

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
        if (!cib_only && pe__is_guest_or_remote_node(node)) {
            node = pe__current_node(node->details->remote_rsc);
            if (node == NULL) {
                out->err(out, "No cluster connection to Pacemaker Remote node %s detected",
                         host_uname);
                return ENOTCONN;
            }
            router_node = node->details->uname;
        }
    }

    if (rsc->clone_name) {
        rsc_api_id = rsc->clone_name;
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
rsc_fail_name(pe_resource_t *rsc)
{
    const char *name = (rsc->clone_name? rsc->clone_name : rsc->id);

    return pcmk_is_set(rsc->flags, pe_rsc_unique)? strdup(name) : clone_strip(name);
}

// \return Standard Pacemaker return code
static int
clear_rsc_history(pcmk_ipc_api_t *controld_api, const char *host_uname,
                  const char *rsc_id, pe_working_set_t *data_set)
{
    int rc = pcmk_rc_ok;

    /* Erase the resource's entire LRM history in the CIB, even if we're only
     * clearing a single operation's fail count. If we erased only entries for a
     * single operation, we might wind up with a wrong idea of the current
     * resource state, and we might not re-probe the resource.
     */
    rc = send_lrm_rsc_op(controld_api, false, host_uname, rsc_id, data_set);
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
                   const char *interval_spec, pe_working_set_t *data_set)
{
    int rc = pcmk_rc_ok;
    const char *failed_value = NULL;
    const char *failed_id = NULL;
    const char *interval_ms_s = NULL;
    GHashTable *rscs = NULL;
    GHashTableIter iter;

    /* Create a hash table to use as a set of resources to clean. This lets us
     * clean each resource only once (per node) regardless of how many failed
     * operations it has.
     */
    rscs = pcmk__strkey_table(NULL, NULL);

    // Normalize interval to milliseconds for comparison to history entry
    if (operation) {
        interval_ms_s = crm_strdup_printf("%u",
                                          crm_parse_interval_spec(interval_spec));
    }

    for (xmlNode *xml_op = pcmk__xml_first_child(data_set->failed);
         xml_op != NULL;
         xml_op = pcmk__xml_next(xml_op)) {

        failed_id = crm_element_value(xml_op, XML_LRM_ATTR_RSCID);
        if (failed_id == NULL) {
            // Malformed history entry, should never happen
            continue;
        }

        // No resource specified means all resources match
        if (rsc_id) {
            pe_resource_t *fail_rsc = pe_find_resource_with_flags(data_set->resources,
                                                                  failed_id,
                                                                  pe_find_renamed|pe_find_anon);

            if (!fail_rsc || !pcmk__str_eq(rsc_id, fail_rsc->id, pcmk__str_casei)) {
                continue;
            }
        }

        // Host name should always have been provided by this point
        failed_value = crm_element_value(xml_op, XML_ATTR_UNAME);
        if (!pcmk__str_eq(node_name, failed_value, pcmk__str_casei)) {
            continue;
        }

        // No operation specified means all operations match
        if (operation) {
            failed_value = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
            if (!pcmk__str_eq(operation, failed_value, pcmk__str_casei)) {
                continue;
            }

            // Interval (if operation was specified) defaults to 0 (not all)
            failed_value = crm_element_value(xml_op, XML_LRM_ATTR_INTERVAL_MS);
            if (!pcmk__str_eq(interval_ms_s, failed_value, pcmk__str_casei)) {
                continue;
            }
        }

        g_hash_table_add(rscs, (gpointer) failed_id);
    }

    g_hash_table_iter_init(&iter, rscs);
    while (g_hash_table_iter_next(&iter, (gpointer *) &failed_id, NULL)) {
        crm_debug("Erasing failures of %s on %s", failed_id, node_name);
        rc = clear_rsc_history(controld_api, node_name, failed_id, data_set);
        if (rc != pcmk_rc_ok) {
            return rc;
        }
    }
    g_hash_table_destroy(rscs);
    return rc;
}

// \return Standard Pacemaker return code
static int
clear_rsc_fail_attrs(pe_resource_t *rsc, const char *operation,
                     const char *interval_spec, pe_node_t *node)
{
    int rc = pcmk_rc_ok;
    int attr_options = pcmk__node_attr_none;
    char *rsc_name = rsc_fail_name(rsc);

    if (pe__is_guest_or_remote_node(node)) {
        attr_options |= pcmk__node_attr_remote;
    }
    rc = pcmk__node_attr_request_clear(NULL, node->details->uname, rsc_name,
                                       operation, interval_spec, NULL,
                                       attr_options);
    free(rsc_name);
    return rc;
}

// \return Standard Pacemaker return code
int
cli_resource_delete(pcmk_ipc_api_t *controld_api, const char *host_uname,
                    pe_resource_t *rsc, const char *operation,
                    const char *interval_spec, bool just_failures,
                    pe_working_set_t *data_set, gboolean force)
{
    pcmk__output_t *out = data_set->priv;
    int rc = pcmk_rc_ok;
    pe_node_t *node = NULL;

    if (rsc == NULL) {
        return ENXIO;

    } else if (rsc->children) {
        GList *lpc = NULL;

        for (lpc = rsc->children; lpc != NULL; lpc = lpc->next) {
            pe_resource_t *child = (pe_resource_t *) lpc->data;

            rc = cli_resource_delete(controld_api, host_uname, child, operation,
                                     interval_spec, just_failures, data_set,
                                     force);
            if (rc != pcmk_rc_ok) {
                return rc;
            }
        }
        return pcmk_rc_ok;

    } else if (host_uname == NULL) {
        GList *lpc = NULL;
        GList *nodes = g_hash_table_get_values(rsc->known_on);

        if(nodes == NULL && force) {
            nodes = pcmk__copy_node_list(data_set->nodes, false);

        } else if(nodes == NULL && rsc->exclusive_discover) {
            GHashTableIter iter;
            pe_node_t *node = NULL;

            g_hash_table_iter_init(&iter, rsc->allowed_nodes);
            while (g_hash_table_iter_next(&iter, NULL, (void**)&node)) {
                if(node->weight >= 0) {
                    nodes = g_list_prepend(nodes, node);
                }
            }

        } else if(nodes == NULL) {
            nodes = g_hash_table_get_values(rsc->allowed_nodes);
        }

        for (lpc = nodes; lpc != NULL; lpc = lpc->next) {
            node = (pe_node_t *) lpc->data;

            if (node->details->online) {
                rc = cli_resource_delete(controld_api, node->details->uname,
                                         rsc, operation, interval_spec,
                                         just_failures, data_set, force);
            }
            if (rc != pcmk_rc_ok) {
                g_list_free(nodes);
                return rc;
            }
        }

        g_list_free(nodes);
        return pcmk_rc_ok;
    }

    node = pe_find_node(data_set->nodes, host_uname);

    if (node == NULL) {
        out->err(out, "Unable to clean up %s because node %s not found",
                 rsc->id, host_uname);
        return ENODEV;
    }

    if (!node->details->rsc_discovery_enabled) {
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
                                interval_spec, data_set);
    } else {
        rc = clear_rsc_history(controld_api, host_uname, rsc->id, data_set);
    }
    if (rc != pcmk_rc_ok) {
        out->err(out, "Cleaned %s failures on %s, but unable to clean history: %s",
                 rsc->id, host_uname, pcmk_strerror(rc));
    } else {
        out->info(out, "Cleaned up %s on %s", rsc->id, host_uname);
    }
    return rc;
}

// \return Standard Pacemaker return code
int
cli_cleanup_all(pcmk_ipc_api_t *controld_api, const char *node_name,
                const char *operation, const char *interval_spec,
                pe_working_set_t *data_set)
{
    pcmk__output_t *out = data_set->priv;
    int rc = pcmk_rc_ok;
    int attr_options = pcmk__node_attr_none;
    const char *display_name = node_name? node_name : "all nodes";

    if (controld_api == NULL) {
        out->info(out, "Dry run: skipping clean-up of %s due to CIB_file",
                  display_name);
        return rc;
    }

    if (node_name) {
        pe_node_t *node = pe_find_node(data_set->nodes, node_name);

        if (node == NULL) {
            out->err(out, "Unknown node: %s", node_name);
            return ENXIO;
        }
        if (pe__is_guest_or_remote_node(node)) {
            attr_options |= pcmk__node_attr_remote;
        }
    }

    rc = pcmk__node_attr_request_clear(NULL, node_name, NULL, operation,
                                       interval_spec, NULL, attr_options);
    if (rc != pcmk_rc_ok) {
        out->err(out, "Unable to clean up all failures on %s: %s",
                 display_name, pcmk_rc_str(rc));
        return rc;
    }

    if (node_name) {
        rc = clear_rsc_failures(out, controld_api, node_name, NULL,
                                operation, interval_spec, data_set);
        if (rc != pcmk_rc_ok) {
            out->err(out, "Cleaned all resource failures on %s, but unable to clean history: %s",
                     node_name, pcmk_strerror(rc));
            return rc;
        }
    } else {
        for (GList *iter = data_set->nodes; iter; iter = iter->next) {
            pe_node_t *node = (pe_node_t *) iter->data;

            rc = clear_rsc_failures(out, controld_api, node->details->uname, NULL,
                                    operation, interval_spec, data_set);
            if (rc != pcmk_rc_ok) {
                out->err(out, "Cleaned all resource failures on all nodes, but unable to clean history: %s",
                         pcmk_strerror(rc));
                return rc;
            }
        }
    }

    out->info(out, "Cleaned up all resources on %s", display_name);
    return rc;
}

int
cli_resource_check(pcmk__output_t *out, cib_t * cib_conn, pe_resource_t *rsc)
{
    char *role_s = NULL;
    char *managed = NULL;
    pe_resource_t *parent = uber_parent(rsc);
    int rc = pcmk_rc_no_output;
    resource_checks_t *checks = NULL;

    find_resource_attr(out, cib_conn, XML_NVPAIR_ATTR_VALUE, parent->id,
                       NULL, NULL, NULL, XML_RSC_ATTR_MANAGED, &managed);

    find_resource_attr(out, cib_conn, XML_NVPAIR_ATTR_VALUE, parent->id,
                       NULL, NULL, NULL, XML_RSC_ATTR_TARGET_ROLE, &role_s);

    checks = cli_check_resource(rsc, role_s, managed);

    if (checks->flags != 0 || checks->lock_node != NULL) {
        rc = out->message(out, "resource-check-list", checks);
    }

    free(role_s);
    free(managed);
    free(checks);
    return rc;
}

// \return Standard Pacemaker return code
int
cli_resource_fail(pcmk_ipc_api_t *controld_api, const char *host_uname,
                  const char *rsc_id, pe_working_set_t *data_set)
{
    crm_notice("Failing %s on %s", rsc_id, host_uname);
    return send_lrm_rsc_op(controld_api, true, host_uname, rsc_id, data_set);
}

static GHashTable *
generate_resource_params(pe_resource_t *rsc, pe_node_t *node,
                         pe_working_set_t *data_set)
{
    GHashTable *params = NULL;
    GHashTable *meta = NULL;
    GHashTable *combined = NULL;
    GHashTableIter iter;
    char *key = NULL;
    char *value = NULL;

    combined = pcmk__strkey_table(free, free);

    params = pe_rsc_params(rsc, node, data_set);
    if (params != NULL) {
        g_hash_table_iter_init(&iter, params);
        while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
            g_hash_table_insert(combined, strdup(key), strdup(value));
        }
    }

    meta = pcmk__strkey_table(free, free);
    get_meta_attributes(meta, rsc, node, data_set);
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

bool resource_is_running_on(pe_resource_t *rsc, const char *host)
{
    bool found = true;
    GList *hIter = NULL;
    GList *hosts = NULL;

    if (rsc == NULL) {
        return false;
    }

    rsc->fns->location(rsc, &hosts, TRUE);
    for (hIter = hosts; host != NULL && hIter != NULL; hIter = hIter->next) {
        pe_node_t *node = (pe_node_t *) hIter->data;

        if (pcmk__strcase_any_of(host, node->details->uname, node->details->id, NULL)) {
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
        pe_resource_t *rsc = (pe_resource_t *) rIter->data;

        /* Expand groups to their members, because if we're restarting a member
         * other than the first, we can't otherwise tell which resources are
         * stopping and starting.
         */
        if (rsc->variant == pe_group) {
            active = g_list_concat(active,
                                   get_active_resources(host, rsc->children));
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
 * \brief Upgrade XML to latest schema version and use it as working set input
 *
 * This also updates the working set timestamp to the current time.
 *
 * \param[in] data_set   Working set instance to update
 * \param[in] xml        XML to use as input
 *
 * \return Standard Pacemaker return code
 * \note On success, caller is responsible for freeing memory allocated for
 *       data_set->now.
 * \todo This follows the example of other callers of cli_config_update()
 *       and returns ENOKEY ("Required key not available") if that fails,
 *       but perhaps pcmk_rc_schema_validation would be better in that case.
 */
int
update_working_set_xml(pe_working_set_t *data_set, xmlNode **xml)
{
    if (cli_config_update(xml, NULL, FALSE) == FALSE) {
        return ENOKEY;
    }
    data_set->input = *xml;
    data_set->now = crm_time_new(NULL);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Update a working set's XML input based on a CIB query
 *
 * \param[in] data_set   Data set instance to initialize
 * \param[in] cib        Connection to the CIB manager
 *
 * \return Standard Pacemaker return code
 * \note On success, caller is responsible for freeing memory allocated for
 *       data_set->input and data_set->now.
 */
static int
update_working_set_from_cib(pcmk__output_t *out, pe_working_set_t * data_set,
                            cib_t *cib)
{
    xmlNode *cib_xml_copy = NULL;
    int rc = pcmk_rc_ok;

    rc = cib->cmds->query(cib, NULL, &cib_xml_copy, cib_scope_local | cib_sync_call);
    rc = pcmk_legacy2rc(rc);

    if (rc != pcmk_rc_ok) {
        out->err(out, "Could not obtain the current CIB: %s (%d)", pcmk_strerror(rc), rc);
        return rc;
    }
    rc = update_working_set_xml(data_set, &cib_xml_copy);
    if (rc != pcmk_rc_ok) {
        out->err(out, "Could not upgrade the current CIB XML");
        free_xml(cib_xml_copy);
        return rc;
    }

    return rc;
}

// \return Standard Pacemaker return code
static int
update_dataset(cib_t *cib, pe_working_set_t * data_set, bool simulate)
{
    char *pid = NULL;
    char *shadow_file = NULL;
    cib_t *shadow_cib = NULL;
    int rc = pcmk_rc_ok;

    pcmk__output_t *out = data_set->priv;

    pe_reset_working_set(data_set);
    pe__set_working_set_flags(data_set, pe_flag_no_counts|pe_flag_no_compat);
    rc = update_working_set_from_cib(out, data_set, cib);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    if(simulate) {
        bool prev_quiet = false;

        pid = pcmk__getpid_s();
        shadow_cib = cib_shadow_new(pid);
        shadow_file = get_shadow_file(pid);

        if (shadow_cib == NULL) {
            out->err(out, "Could not create shadow cib: '%s'", pid);
            rc = ENXIO;
            goto done;
        }

        rc = write_xml_file(data_set->input, shadow_file, FALSE);

        if (rc < 0) {
            out->err(out, "Could not populate shadow cib: %s (%d)", pcmk_strerror(rc), rc);
            goto done;
        }

        rc = shadow_cib->cmds->signon(shadow_cib, crm_system_name, cib_command);
        rc = pcmk_legacy2rc(rc);

        if (rc != pcmk_rc_ok) {
            out->err(out, "Could not connect to shadow cib: %s (%d)", pcmk_strerror(rc), rc);
            goto done;
        }

        pcmk__schedule_actions(data_set->input,
                               pe_flag_no_counts|pe_flag_no_compat, data_set);

        prev_quiet = out->is_quiet(out);
        out->quiet = true;
        pcmk__simulate_transition(data_set, shadow_cib, NULL);
        out->quiet = prev_quiet;

        rc = update_dataset(shadow_cib, data_set, false);

    } else {
        cluster_status(data_set);
    }

  done:
    /* Do not free data_set->input here, we need rsc->xml to be valid later on */
    cib_delete(shadow_cib);
    free(pid);

    if(shadow_file) {
        unlink(shadow_file);
        free(shadow_file);
    }

    return rc;
}

static int
max_delay_for_resource(pe_working_set_t * data_set, pe_resource_t *rsc) 
{
    int delay = 0;
    int max_delay = 0;

    if(rsc && rsc->children) {
        GList *iter = NULL;

        for(iter = rsc->children; iter; iter = iter->next) {
            pe_resource_t *child = (pe_resource_t *)iter->data;

            delay = max_delay_for_resource(data_set, child);
            if(delay > max_delay) {
                double seconds = delay / 1000.0;
                crm_trace("Calculated new delay of %.1fs due to %s", seconds, child->id);
                max_delay = delay;
            }
        }

    } else if(rsc) {
        char *key = crm_strdup_printf("%s_%s_0", rsc->id, RSC_STOP);
        pe_action_t *stop = custom_action(rsc, key, RSC_STOP, NULL, TRUE, FALSE, data_set);
        const char *value = g_hash_table_lookup(stop->meta, XML_ATTR_TIMEOUT);
        long long result_ll;

        if ((pcmk__scan_ll(value, &result_ll, -1LL) == pcmk_rc_ok)
            && (result_ll >= 0) && (result_ll <= INT_MAX)) {
            max_delay = (int) result_ll;
        } else {
            max_delay = -1;
        }
        pe_free_action(stop);
    }

    return max_delay;
}

static int
max_delay_in(pe_working_set_t * data_set, GList *resources) 
{
    int max_delay = 0;
    GList *item = NULL;

    for (item = resources; item != NULL; item = item->next) {
        int delay = 0;
        pe_resource_t *rsc = pe_find_resource(data_set->resources, (const char *)item->data);

        delay = max_delay_for_resource(data_set, rsc);

        if(delay > max_delay) {
            double seconds = delay / 1000.0;
            crm_trace("Calculated new delay of %.1fs due to %s", seconds, rsc->id);
            max_delay = delay;
        }
    }

    return 5 + (max_delay / 1000);
}

#define waiting_for_starts(d, r, h) ((d != NULL) || \
                                    (!resource_is_running_on((r), (h))))

/*!
 * \internal
 * \brief Restart a resource (on a particular host if requested).
 *
 * \param[in] rsc        The resource to restart
 * \param[in] host       The host to restart the resource on (or NULL for all)
 * \param[in] timeout_ms Consider failed if actions do not complete in this time
 *                       (specified in milliseconds, but a two-second
 *                       granularity is actually used; if 0, a timeout will be
 *                       calculated based on the resource timeout)
 * \param[in] cib        Connection to the CIB manager
 *
 * \return Standard Pacemaker return code (exits on certain failures)
 */
int
cli_resource_restart(pcmk__output_t *out, pe_resource_t *rsc, const char *host,
                     const char *move_lifetime, int timeout_ms, cib_t *cib,
                     int cib_options, gboolean promoted_role_only, gboolean force)
{
    int rc = pcmk_rc_ok;
    int lpc = 0;
    int before = 0;
    int step_timeout_s = 0;
    int sleep_interval = 2;
    int timeout = timeout_ms / 1000;

    bool stop_via_ban = false;
    char *rsc_id = NULL;
    char *orig_target_role = NULL;

    GList *list_delta = NULL;
    GList *target_active = NULL;
    GList *current_active = NULL;
    GList *restart_target_active = NULL;

    pe_working_set_t *data_set = NULL;

    if (!resource_is_running_on(rsc, host)) {
        const char *id = rsc->clone_name?rsc->clone_name:rsc->id;
        if(host) {
            out->err(out, "%s is not running on %s and so cannot be restarted", id, host);
        } else {
            out->err(out, "%s is not running anywhere and so cannot be restarted", id);
        }
        return ENXIO;
    }

    rsc_id = strdup(rsc->id);
    if ((pe_rsc_is_clone(rsc) || pe_bundle_replicas(rsc)) && host) {
        stop_via_ban = true;
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

    data_set = pe_new_working_set();
    if (data_set == NULL) {
        crm_perror(LOG_ERR, "Could not allocate working set");
        rc = ENOMEM;
        goto done;
    }

    data_set->priv = out;
    rc = update_dataset(cib, data_set, false);

    if(rc != pcmk_rc_ok) {
        out->err(out, "Could not get new resource list: %s (%d)", pcmk_strerror(rc), rc);
        goto done;
    }

    restart_target_active = get_active_resources(host, data_set->resources);
    current_active = get_active_resources(host, data_set->resources);

    dump_list(current_active, "Origin");

    if (stop_via_ban) {
        /* Stop the clone or bundle instance by banning it from the host */
        out->quiet = true;
        rc = cli_resource_ban(out, rsc_id, host, move_lifetime, NULL, cib,
                              cib_options, promoted_role_only);

    } else {
        /* Stop the resource by setting target-role to Stopped.
         * Remember any existing target-role so we can restore it later
         * (though it only makes any difference if it's Unpromoted).
         */
        char *lookup_id = clone_strip(rsc->id);

        find_resource_attr(out, cib, XML_NVPAIR_ATTR_VALUE, lookup_id, NULL, NULL,
                           NULL, XML_RSC_ATTR_TARGET_ROLE, &orig_target_role);
        free(lookup_id);
        rc = cli_resource_update_attribute(rsc, rsc_id, NULL, XML_TAG_META_SETS,
                                           NULL, XML_RSC_ATTR_TARGET_ROLE,
                                           RSC_STOPPED, FALSE, cib, cib_options,
                                           data_set, force);
    }
    if(rc != pcmk_rc_ok) {
        out->err(out, "Could not set target-role for %s: %s (%d)", rsc_id, pcmk_strerror(rc), rc);
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

    rc = update_dataset(cib, data_set, true);
    if(rc != pcmk_rc_ok) {
        out->err(out, "Could not determine which resources would be stopped");
        goto failure;
    }

    target_active = get_active_resources(host, data_set->resources);
    dump_list(target_active, "Target");

    list_delta = pcmk__subtract_lists(current_active, target_active, (GCompareFunc) strcmp);
    out->info(out, "Waiting for %d resources to stop:", g_list_length(list_delta));
    display_list(out, list_delta, " * ");

    step_timeout_s = timeout / sleep_interval;
    while (list_delta != NULL) {
        before = g_list_length(list_delta);
        if(timeout_ms == 0) {
            step_timeout_s = max_delay_in(data_set, list_delta) / sleep_interval;
        }

        /* We probably don't need the entire step timeout */
        for(lpc = 0; (lpc < step_timeout_s) && (list_delta != NULL); lpc++) {
            sleep(sleep_interval);
            if(timeout) {
                timeout -= sleep_interval;
                crm_trace("%ds remaining", timeout);
            }
            rc = update_dataset(cib, data_set, FALSE);
            if(rc != pcmk_rc_ok) {
                out->err(out, "Could not determine which resources were stopped");
                goto failure;
            }

            if (current_active != NULL) {
                g_list_free_full(current_active, free);
                current_active = NULL;
            }
            current_active = get_active_resources(host, data_set->resources);
            g_list_free(list_delta);
            list_delta = NULL;
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
        rc = cli_resource_clear(rsc_id, host, NULL, cib, cib_options, true, force);

    } else if (orig_target_role) {
        rc = cli_resource_update_attribute(rsc, rsc_id, NULL, XML_TAG_META_SETS,
                                           NULL, XML_RSC_ATTR_TARGET_ROLE,
                                           orig_target_role, FALSE, cib,
                                           cib_options, data_set, force);
        free(orig_target_role);
        orig_target_role = NULL;
    } else {
        rc = cli_resource_delete_attribute(rsc, rsc_id, NULL, XML_TAG_META_SETS,
                                           NULL, XML_RSC_ATTR_TARGET_ROLE, cib,
                                           cib_options, data_set, force);
    }

    if(rc != pcmk_rc_ok) {
        out->err(out, "Could not unset target-role for %s: %s (%d)", rsc_id, pcmk_strerror(rc), rc);
        goto done;
    }

    if (target_active != NULL) {
        g_list_free_full(target_active, free);
        target_active = NULL;
    }
    target_active = restart_target_active;
    list_delta = pcmk__subtract_lists(target_active, current_active, (GCompareFunc) strcmp);
    out->info(out, "Waiting for %d resources to start again:", g_list_length(list_delta));
    display_list(out, list_delta, " * ");

    step_timeout_s = timeout / sleep_interval;
    while (waiting_for_starts(list_delta, rsc, host)) {
        before = g_list_length(list_delta);
        if(timeout_ms == 0) {
            step_timeout_s = max_delay_in(data_set, list_delta) / sleep_interval;
        }

        /* We probably don't need the entire step timeout */
        for (lpc = 0; (lpc < step_timeout_s) && waiting_for_starts(list_delta, rsc, host); lpc++) {

            sleep(sleep_interval);
            if(timeout) {
                timeout -= sleep_interval;
                crm_trace("%ds remaining", timeout);
            }

            rc = update_dataset(cib, data_set, false);
            if(rc != pcmk_rc_ok) {
                out->err(out, "Could not determine which resources were started");
                goto failure;
            }

            if (current_active != NULL) {
                g_list_free_full(current_active, free);
                current_active = NULL;
            }

            /* It's OK if dependent resources moved to a different node,
             * so we check active resources on all nodes.
             */
            current_active = get_active_resources(NULL, data_set->resources);
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
        cli_resource_clear(rsc_id, host, NULL, cib, cib_options, true, force);
    } else if (orig_target_role) {
        cli_resource_update_attribute(rsc, rsc_id, NULL, XML_TAG_META_SETS, NULL,
                                      XML_RSC_ATTR_TARGET_ROLE, orig_target_role,
                                      FALSE, cib, cib_options, data_set, force);
        free(orig_target_role);
    } else {
        cli_resource_delete_attribute(rsc, rsc_id, NULL, XML_TAG_META_SETS, NULL,
                                      XML_RSC_ATTR_TARGET_ROLE, cib, cib_options,
                                      data_set, force);
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
    pe_free_working_set(data_set);
    return rc;
}

static inline bool action_is_pending(pe_action_t *action)
{
    if (pcmk_any_flags_set(action->flags, pe_action_optional|pe_action_pseudo)
        || !pcmk_is_set(action->flags, pe_action_runnable)
        || pcmk__str_eq("notify", action->task, pcmk__str_casei)) {
        return false;
    }
    return true;
}

/*!
 * \internal
 * \brief Return TRUE if any actions in a list are pending
 *
 * \param[in] actions   List of actions to check
 *
 * \return TRUE if any actions in the list are pending, FALSE otherwise
 */
static bool
actions_are_pending(GList *actions)
{
    GList *action;

    for (action = actions; action != NULL; action = action->next) {
        pe_action_t *a = (pe_action_t *)action->data;
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
        pe_action_t *a = (pe_action_t *) action->data;

        if (!action_is_pending(a)) {
            continue;
        }

        if (a->node) {
            out->info(out, "\tAction %d: %s\ton %s", a->id, a->uuid, a->node->details->uname);
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
 * \param[in] timeout_ms Consider failed if actions do not complete in this time
 *                       (specified in milliseconds, but one-second granularity
 *                       is actually used; if 0, a default will be used)
 * \param[in] cib        Connection to the CIB manager
 *
 * \return Standard Pacemaker return code
 */
int
wait_till_stable(pcmk__output_t *out, int timeout_ms, cib_t * cib)
{
    pe_working_set_t *data_set = NULL;
    int rc = pcmk_rc_ok;
    int timeout_s = timeout_ms? ((timeout_ms + 999) / 1000) : WAIT_DEFAULT_TIMEOUT_S;
    time_t expire_time = time(NULL) + timeout_s;
    time_t time_diff;
    bool printed_version_warning = out->is_quiet(out); // i.e. don't print if quiet

    data_set = pe_new_working_set();
    if (data_set == NULL) {
        return ENOMEM;
    }

    do {

        /* Abort if timeout is reached */
        time_diff = expire_time - time(NULL);
        if (time_diff > 0) {
            crm_info("Waiting up to %ld seconds for cluster actions to complete", time_diff);
        } else {
            print_pending_actions(out, data_set->actions);
            pe_free_working_set(data_set);
            return ETIME;
        }
        if (rc == pcmk_rc_ok) { /* this avoids sleep on first loop iteration */
            sleep(WAIT_SLEEP_S);
        }

        /* Get latest transition graph */
        pe_reset_working_set(data_set);
        rc = update_working_set_from_cib(out, data_set, cib);
        if (rc != pcmk_rc_ok) {
            pe_free_working_set(data_set);
            return rc;
        }
        pcmk__schedule_actions(data_set->input,
                               pe_flag_no_counts|pe_flag_no_compat, data_set);

        if (!printed_version_warning) {
            /* If the DC has a different version than the local node, the two
             * could come to different conclusions about what actions need to be
             * done. Warn the user in this case.
             *
             * @TODO A possible long-term solution would be to reimplement the
             * wait as a new controller operation that would be forwarded to the
             * DC. However, that would have potential problems of its own.
             */
            const char *dc_version = g_hash_table_lookup(data_set->config_hash,
                                                         "dc-version");

            if (!pcmk__str_eq(dc_version, PACEMAKER_VERSION "-" BUILD_VERSION, pcmk__str_casei)) {
                out->info(out, "warning: wait option may not work properly in "
                          "mixed-version cluster");
                printed_version_warning = true;
            }
        }

    } while (actions_are_pending(data_set->actions));

    pe_free_working_set(data_set);
    return rc;
}

static const char *
get_action(const char *rsc_action) {
    const char *action = NULL;

    if (pcmk__str_eq(rsc_action, "validate", pcmk__str_casei)) {
        action = "validate-all";

    } else if (pcmk__str_eq(rsc_action, "force-check", pcmk__str_casei)) {
        action = "monitor";

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
 * \param[in] params       Resource parameters that will be passed to agent
 * \param[in] timeout_ms   Action timeout (in milliseconds)
 * \param[in] check_level  OCF check level
 * \param[in] verbosity    Verbosity level
 */
static void
set_agent_environment(GHashTable *params, int timeout_ms, int check_level,
                      int verbosity)
{
    g_hash_table_insert(params, strdup("CRM_meta_timeout"),
                        crm_strdup_printf("%d", timeout_ms));

    g_hash_table_insert(params, strdup(XML_ATTR_CRM_VERSION),
                        strdup(CRM_FEATURE_SET));

    if (check_level >= 0) {
        char *level = crm_strdup_printf("%d", check_level);

        setenv("OCF_CHECK_LEVEL", level, 1);
        free(level);
    }

    setenv("HA_debug", (verbosity > 0)? "1" : "0", 1);
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
 * \param[in] params     Parameters to be passed to agent
 * \param[in] overrides  Parameters to override (or NULL if none)
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
            g_hash_table_replace(params, strdup(name), strdup(value));
        }
    }
}

crm_exit_t
cli_resource_execute_from_params(pcmk__output_t *out, const char *rsc_name,
                                 const char *rsc_class, const char *rsc_prov,
                                 const char *rsc_type, const char *rsc_action,
                                 GHashTable *params, GHashTable *override_hash,
                                 int timeout_ms, int resource_verbose, gboolean force,
                                 int check_level)
{
    const char *class = rsc_class;
    const char *action = get_action(rsc_action);
    crm_exit_t exit_code = CRM_EX_OK;
    svc_action_t *op = NULL;

    // If no timeout was provided, use the same default as the cluster
    if (timeout_ms == 0) {
        timeout_ms = crm_get_msec(CRM_DEFAULT_OP_TIMEOUT_S);
    }

    set_agent_environment(params, timeout_ms, check_level, resource_verbose);
    apply_overrides(params, override_hash);

    op = services__create_resource_action(rsc_name? rsc_name : "test",
                                          rsc_class, rsc_prov, rsc_type, action,
                                          0, timeout_ms, params, 0);
    if (op == NULL) {
        out->err(out, "Could not execute %s using %s%s%s:%s: %s",
                 action, rsc_class, (rsc_prov? ":" : ""),
                 (rsc_prov? rsc_prov : ""), rsc_type, strerror(ENOMEM));
        g_hash_table_destroy(params);
        return CRM_EX_OSERR;
    }

    if (pcmk__str_eq(rsc_class, PCMK_RESOURCE_CLASS_SERVICE, pcmk__str_casei)) {
        class = resources_find_service_class(rsc_type);
    }
    if (!pcmk__strcase_any_of(class, PCMK_RESOURCE_CLASS_OCF,
                              PCMK_RESOURCE_CLASS_LSB, NULL)) {
        services__format_result(op, CRM_EX_UNIMPLEMENT_FEATURE, PCMK_EXEC_ERROR,
                                "Manual execution of the %s standard "
                                "is unsupported", crm_str(class));
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

crm_exit_t
cli_resource_execute(pe_resource_t *rsc, const char *requested_name,
                     const char *rsc_action, GHashTable *override_hash,
                     int timeout_ms, cib_t * cib, pe_working_set_t *data_set,
                     int resource_verbose, gboolean force, int check_level)
{
    pcmk__output_t *out = data_set->priv;
    crm_exit_t exit_code = CRM_EX_OK;
    const char *rid = NULL;
    const char *rtype = NULL;
    const char *rprov = NULL;
    const char *rclass = NULL;
    GHashTable *params = NULL;

    if (pcmk__strcase_any_of(rsc_action, "force-start", "force-demote",
                                    "force-promote", NULL)) {
        if(pe_rsc_is_clone(rsc)) {
            GList *nodes = cli_resource_search(rsc, requested_name, data_set);
            if(nodes != NULL && force == FALSE) {
                out->err(out, "It is not safe to %s %s here: the cluster claims it is already active",
                         rsc_action, rsc->id);
                out->err(out, "Try setting target-role=Stopped first or specifying "
                         "the force option");
                return CRM_EX_UNSAFE;
            }

            g_list_free_full(nodes, free);
        }
    }

    if(pe_rsc_is_clone(rsc)) {
        /* Grab the first child resource in the hope it's not a group */
        rsc = rsc->children->data;
    }

    if(rsc->variant == pe_group) {
        out->err(out, "Sorry, the %s option doesn't support group resources", rsc_action);
        return CRM_EX_UNIMPLEMENT_FEATURE;
    } else if (rsc->variant == pe_container || pe_rsc_is_bundled(rsc)) {
        out->err(out, "Sorry, the %s option doesn't support bundled resources", rsc_action);
        return CRM_EX_UNIMPLEMENT_FEATURE;
    }

    rclass = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    rprov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
    rtype = crm_element_value(rsc->xml, XML_ATTR_TYPE);

    params = generate_resource_params(rsc, NULL /* @TODO use local node */,
                                      data_set);

    if (timeout_ms == 0) {
        timeout_ms = pe_get_configured_timeout(rsc, get_action(rsc_action), data_set);
    }

    rid = pe_rsc_is_anon_clone(rsc->parent)? requested_name : rsc->id;

    exit_code = cli_resource_execute_from_params(out, rid, rclass, rprov, rtype, rsc_action,
                                                 params, override_hash, timeout_ms,
                                                 resource_verbose, force, check_level);
    return exit_code;
}

// \return Standard Pacemaker return code
int
cli_resource_move(pe_resource_t *rsc, const char *rsc_id, const char *host_name,
                  const char *move_lifetime, cib_t *cib, int cib_options,
                  pe_working_set_t *data_set, gboolean promoted_role_only,
                  gboolean force)
{
    pcmk__output_t *out = data_set->priv;
    int rc = pcmk_rc_ok;
    unsigned int count = 0;
    pe_node_t *current = NULL;
    pe_node_t *dest = pe_find_node(data_set->nodes, host_name);
    bool cur_is_dest = false;

    if (dest == NULL) {
        return pcmk_rc_node_unknown;
    }

    if (promoted_role_only && !pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        pe_resource_t *p = uber_parent(rsc);

        if (pcmk_is_set(p->flags, pe_rsc_promotable)) {
            out->info(out, "Using parent '%s' for move instead of '%s'.", rsc->id, rsc_id);
            rsc_id = p->id;
            rsc = p;

        } else {
            out->info(out, "Ignoring master option: %s is not promotable", rsc_id);
            promoted_role_only = FALSE;
        }
    }

    current = pe__find_active_requires(rsc, &count);

    if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        GList *iter = NULL;
        unsigned int promoted_count = 0;
        pe_node_t *promoted_node = NULL;

        for(iter = rsc->children; iter; iter = iter->next) {
            pe_resource_t *child = (pe_resource_t *)iter->data;
            enum rsc_role_e child_role = child->fns->state(child, TRUE);

            if (child_role == RSC_ROLE_PROMOTED) {
                rsc = child;
                promoted_node = pe__current_node(child);
                promoted_count++;
            }
        }
        if (promoted_role_only || (promoted_count != 0)) {
            count = promoted_count;
            current = promoted_node;
        }

    }

    if (count > 1) {
        if (pe_rsc_is_clone(rsc)) {
            current = NULL;
        } else {
            return pcmk_rc_multiple;
        }
    }

    if (current && (current->details == dest->details)) {
        cur_is_dest = true;
        if (force) {
            crm_info("%s is already %s on %s, reinforcing placement with location constraint.",
                     rsc_id, promoted_role_only?"promoted":"active", dest->details->uname);
        } else {
            return pcmk_rc_already;
        }
    }

    /* Clear any previous prefer constraints across all nodes. */
    cli_resource_clear(rsc_id, NULL, data_set->nodes, cib, cib_options, false, force);

    /* Clear any previous ban constraints on 'dest'. */
    cli_resource_clear(rsc_id, dest->details->uname, data_set->nodes, cib,
                       cib_options, TRUE, force);

    /* Record an explicit preference for 'dest' */
    rc = cli_resource_prefer(out, rsc_id, dest->details->uname, move_lifetime,
                             cib, cib_options, promoted_role_only);

    crm_trace("%s%s now prefers node %s%s",
              rsc->id, (promoted_role_only? " (promoted)" : ""),
              dest->details->uname, force?"(forced)":"");

    /* only ban the previous location if current location != destination location.
     * it is possible to use -M to enforce a location without regard of where the
     * resource is currently located */
    if (force && !cur_is_dest) {
        /* Ban the original location if possible */
        if(current) {
            (void)cli_resource_ban(out, rsc_id, current->details->uname, move_lifetime,
                                   NULL, cib, cib_options, promoted_role_only);

        } else if(count > 1) {
            out->info(out, "Resource '%s' is currently %s in %d locations. "
                      "One may now move to %s",
                      rsc_id, (promoted_role_only? "promoted" : "active"),
                      count, dest->details->uname);
            out->info(out, "To prevent '%s' from being %s at a specific location, "
                      "specify a node.",
                      rsc_id, (promoted_role_only? "promoted" : "active"));

        } else {
            crm_trace("Not banning %s from its current location: not active", rsc_id);
        }
    }

    return rc;
}

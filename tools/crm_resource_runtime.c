/*
 * Copyright 2004-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_resource.h>
#include <crm/common/ipc_controld.h>

int resource_verbose = 0;
bool do_force = FALSE;

const char *attr_set_type = XML_TAG_ATTR_SETS;

static int
do_find_resource(const char *rsc, pe_resource_t * the_rsc, pe_working_set_t * data_set)
{
    int found = 0;
    GListPtr lpc = NULL;

    for (lpc = the_rsc->running_on; lpc != NULL; lpc = lpc->next) {
        pe_node_t *node = (pe_node_t *) lpc->data;

        if (BE_QUIET) {
            fprintf(stdout, "%s\n", node->details->uname);
        } else {
            const char *state = "";

            if (!pe_rsc_is_clone(the_rsc) && the_rsc->fns->state(the_rsc, TRUE) == RSC_ROLE_MASTER) {
                state = "Master";
            }
            fprintf(stdout, "resource %s is running on: %s %s\n", rsc, node->details->uname, state);
        }

        found++;
    }

    if (BE_QUIET == FALSE && found == 0) {
        fprintf(stderr, "resource %s is NOT running\n", rsc);
    }

    return found;
}

int
cli_resource_search(pe_resource_t *rsc, const char *requested_name,
                    pe_working_set_t *data_set)
{
    int found = 0;
    pe_resource_t *parent = uber_parent(rsc);

    if (pe_rsc_is_clone(rsc)) {
        for (GListPtr iter = rsc->children; iter != NULL; iter = iter->next) {
            found += do_find_resource(requested_name, iter->data, data_set);
        }

    /* The anonymous clone children's common ID is supplied */
    } else if (pe_rsc_is_clone(parent)
               && is_not_set(rsc->flags, pe_rsc_unique)
               && rsc->clone_name
               && safe_str_eq(requested_name, rsc->clone_name)
               && safe_str_neq(requested_name, rsc->id)) {

        for (GListPtr iter = parent->children; iter; iter = iter->next) {
            found += do_find_resource(requested_name, iter->data, data_set);
        }

    } else {
        found += do_find_resource(requested_name, rsc, data_set);
    }

    return found;
}

#define XPATH_MAX 1024

static int
find_resource_attr(cib_t * the_cib, const char *attr, const char *rsc, const char *set_type,
                   const char *set_name, const char *attr_id, const char *attr_name, char **value)
{
    int offset = 0;
    int rc = pcmk_ok;
    xmlNode *xml_search = NULL;
    char *xpath_string = NULL;

    if(value) {
        *value = NULL;
    }

    if(the_cib == NULL) {
        return -ENOTCONN;
    }

    xpath_string = calloc(1, XPATH_MAX);
    offset +=
        snprintf(xpath_string + offset, XPATH_MAX - offset, "%s", get_object_path("resources"));

    offset += snprintf(xpath_string + offset, XPATH_MAX - offset, "//*[@id=\"%s\"]", rsc);

    if (set_type) {
        offset += snprintf(xpath_string + offset, XPATH_MAX - offset, "/%s", set_type);
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

    if (rc != pcmk_ok) {
        goto bail;
    }

    crm_log_xml_debug(xml_search, "Match");
    if (xml_has_children(xml_search)) {
        xmlNode *child = NULL;

        rc = -EINVAL;
        printf("Multiple attributes match name=%s\n", attr_name);

        for (child = __xml_first_child(xml_search); child != NULL; child = __xml_next(child)) {
            printf("  Value: %s \t(id=%s)\n",
                   crm_element_value(child, XML_NVPAIR_ATTR_VALUE), ID(child));
        }

    } else if(value) {
        const char *tmp = crm_element_value(xml_search, attr);

        if (tmp) {
            *value = strdup(tmp);
        }
    }

  bail:
    free(xpath_string);
    free_xml(xml_search);
    return rc;
}

/* PRIVATE. Use the find_matching_attr_resources instead. */
static void
find_matching_attr_resources_recursive(GList/* <pe_resource_t*> */ ** result, pe_resource_t * rsc, const char * rsc_id, 
		                       const char * attr_set, const char * attr_id,
                                       const char * attr_name, cib_t * cib, const char * cmd, int depth)
{
    int rc = pcmk_ok;
    char *lookup_id = clone_strip(rsc->id);
    char *local_attr_id = NULL;

    /* visit the children */
    for(GList *gIter = rsc->children; gIter; gIter = gIter->next) {
        find_matching_attr_resources_recursive(result, (pe_resource_t*)gIter->data, rsc_id, attr_set, attr_id, attr_name, cib, cmd, depth+1);
        /* do it only once for clones */
        if(pe_clone == rsc->variant) {
            break;
        }
    }

    rc = find_resource_attr(cib, XML_ATTR_ID, lookup_id, attr_set_type, attr_set, attr_id, attr_name, &local_attr_id);
    /* Post-order traversal. 
     * The root is always on the list and it is the last item. */
    if((0 == depth) || (pcmk_ok == rc)) {
        /* push the head */
        *result = g_list_append(*result, rsc);
    }

    free(local_attr_id);
    free(lookup_id);
}


/* The result is a linearized pre-ordered tree of resources. */
static GList/*<pe_resource_t*>*/ *
find_matching_attr_resources(pe_resource_t * rsc, const char * rsc_id, const char * attr_set, const char * attr_id,
                            const char * attr_name, cib_t * cib, const char * cmd)
{
    int rc = pcmk_ok;
    char *lookup_id = NULL;
    char *local_attr_id = NULL;
    GList * result = NULL;
    /* If --force is used, update only the requested resource (clone or primitive).
     * Otherwise, if the primitive has the attribute, use that.
     * Otherwise use the clone. */
    if(do_force == TRUE) {
        return g_list_append(result, rsc);
    }
    if(rsc->parent && pe_clone == rsc->parent->variant) {
        int rc = pcmk_ok;
        char *local_attr_id = NULL;
        rc = find_resource_attr(cib, XML_ATTR_ID, rsc_id, attr_set_type, attr_set, attr_id, attr_name, &local_attr_id);
        free(local_attr_id);

        if(rc != pcmk_ok) {
            rsc = rsc->parent;
            if (BE_QUIET == FALSE) {
                printf("Performing %s of '%s' on '%s', the parent of '%s'\n", cmd, attr_name, rsc->id, rsc_id);
            }
        }
        return g_list_append(result, rsc);
    } else if(rsc->parent == NULL && rsc->children && pe_clone == rsc->variant) {
        pe_resource_t *child = rsc->children->data;

        if(child->variant == pe_native) {
            lookup_id = clone_strip(child->id); /* Could be a cloned group! */
            rc = find_resource_attr(cib, XML_ATTR_ID, lookup_id, attr_set_type, attr_set, attr_id, attr_name, &local_attr_id);

            if(rc == pcmk_ok) {
                rsc = child;
                if (BE_QUIET == FALSE) {
                    printf("A value for '%s' already exists in child '%s', performing %s on that instead of '%s'\n", attr_name, lookup_id, cmd, rsc_id);
                }
            }

            free(local_attr_id);
            free(lookup_id);
        }
        return g_list_append(result, rsc);
    }
    /* If the resource is a group ==> children inherit the attribute if defined. */
    find_matching_attr_resources_recursive(&result, rsc, rsc_id, attr_set, attr_id, attr_name, cib, cmd, 0);
    return result;
}

int
cli_resource_update_attribute(pe_resource_t *rsc, const char *requested_name,
                              const char *attr_set, const char *attr_id,
                              const char *attr_name, const char *attr_value,
                              bool recursive, cib_t *cib,
                              pe_working_set_t *data_set)
{
    int rc = pcmk_ok;
    static bool need_init = TRUE;

    char *local_attr_id = NULL;
    char *local_attr_set = NULL;

    GList/*<pe_resource_t*>*/ *resources = NULL;
    const char *common_attr_id = attr_id;

    if(attr_id == NULL
       && do_force == FALSE
       && find_resource_attr(
           cib, XML_ATTR_ID, uber_parent(rsc)->id, NULL, NULL, NULL, attr_name, NULL) == -EINVAL) {
        printf("\n");
    }

    if (safe_str_eq(attr_set_type, XML_TAG_ATTR_SETS)) {
        if (do_force == FALSE) {
            rc = find_resource_attr(cib, XML_ATTR_ID, uber_parent(rsc)->id,
                                    XML_TAG_META_SETS, attr_set, attr_id,
                                    attr_name, &local_attr_id);
            if (rc == pcmk_ok && BE_QUIET == FALSE) {
                printf("WARNING: There is already a meta attribute for '%s' called '%s' (id=%s)\n",
                       uber_parent(rsc)->id, attr_name, local_attr_id);
                printf("         Delete '%s' first or use the force option to override\n",
                       local_attr_id);
            }
            free(local_attr_id);
            if (rc == pcmk_ok) {
                return -ENOTUNIQ;
            }
        }
        resources = g_list_append(resources, rsc);

    } else {
        resources = find_matching_attr_resources(rsc, requested_name, attr_set,
                                                 attr_id, attr_name, cib, "update");
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
        rc = find_resource_attr(cib, XML_ATTR_ID, lookup_id, attr_set_type, attr_set, attr_id, attr_name,
                                &local_attr_id);

        if (rc == pcmk_ok) {
            crm_debug("Found a match for name=%s: id=%s", attr_name, local_attr_id);
            attr_id = local_attr_id;

        } else if (rc != -ENXIO) {
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
        if (rc == pcmk_ok && BE_QUIET == FALSE) {
            printf("Set '%s' option: id=%s%s%s%s%s value=%s\n", lookup_id, local_attr_id,
                   attr_set ? " set=" : "", attr_set ? attr_set : "",
                   attr_name ? " name=" : "", attr_name ? attr_name : "", attr_value);
        }

        free_xml(xml_top);

        free(lookup_id);
        free(local_attr_id);
        free(local_attr_set);

        if(recursive && safe_str_eq(attr_set_type, XML_TAG_META_SETS)) {
            GListPtr lpc = NULL;

            if(need_init) {
                xmlNode *cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS, data_set->input);

                need_init = FALSE;
                unpack_constraints(cib_constraints, data_set);

                for (lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
                    pe_resource_t *r = (pe_resource_t *) lpc->data;

                    clear_bit(r->flags, pe_rsc_allocating);
                }
            }

            crm_debug("Looking for dependencies %p", rsc->rsc_cons_lhs);
            set_bit(rsc->flags, pe_rsc_allocating);
            for (lpc = rsc->rsc_cons_lhs; lpc != NULL; lpc = lpc->next) {
                rsc_colocation_t *cons = (rsc_colocation_t *) lpc->data;
                pe_resource_t *peer = cons->rsc_lh;

                crm_debug("Checking %s %d", cons->id, cons->score);
                if (cons->score > 0 && is_not_set(peer->flags, pe_rsc_allocating)) {
                    /* Don't get into colocation loops */
                    crm_debug("Setting %s=%s for dependent resource %s", attr_name, attr_value, peer->id);
                    cli_resource_update_attribute(peer, peer->id, NULL, NULL,
                                                  attr_name, attr_value, recursive,
                                                  cib, data_set);
                }
            }
        }
    }
    g_list_free(resources);
    return rc;
}

int
cli_resource_delete_attribute(pe_resource_t *rsc, const char *requested_name,
                              const char *attr_set, const char *attr_id,
                              const char *attr_name, cib_t *cib,
                              pe_working_set_t *data_set)
{
    int rc = pcmk_ok;
    GList/*<pe_resource_t*>*/ *resources = NULL;

    if(attr_id == NULL
       && do_force == FALSE
       && find_resource_attr(
           cib, XML_ATTR_ID, uber_parent(rsc)->id, NULL, NULL, NULL, attr_name, NULL) == -EINVAL) {
        printf("\n");
    }

    if(safe_str_eq(attr_set_type, XML_TAG_META_SETS)) {
        resources = find_matching_attr_resources(rsc, requested_name, attr_set,
                                                 attr_id, attr_name, cib, "delete");
    } else {
        resources = g_list_append(resources, rsc);
    }

    for(GList *gIter = resources; gIter; gIter = gIter->next) {
        char *lookup_id = NULL;
        xmlNode *xml_obj = NULL;
        char *local_attr_id = NULL;

        rsc = (pe_resource_t*)gIter->data;

        lookup_id = clone_strip(rsc->id);
        rc = find_resource_attr(cib, XML_ATTR_ID, lookup_id, attr_set_type, attr_set, attr_id, attr_name,
                                &local_attr_id);

        if (rc == -ENXIO) {
            free(lookup_id);
            rc = pcmk_ok;
            continue;

        } else if (rc != pcmk_ok) {
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

        if (rc == pcmk_ok && BE_QUIET == FALSE) {
            printf("Deleted '%s' option: id=%s%s%s%s%s\n", lookup_id, local_attr_id,
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
                const char *host_uname, const char *rsc_id,
                pe_working_set_t *data_set)
{
    const char *router_node = host_uname;
    const char *rsc_api_id = NULL;
    const char *rsc_long_id = NULL;
    const char *rsc_class = NULL;
    const char *rsc_provider = NULL;
    const char *rsc_type = NULL;
    bool cib_only = false;
    pe_resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);

    if (rsc == NULL) {
        CMD_ERR("Resource %s not found", rsc_id);
        return ENXIO;

    } else if (rsc->variant != pe_native) {
        CMD_ERR("We can only process primitive resources, not %s", rsc_id);
        return EINVAL;
    }

    rsc_class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    rsc_provider = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER),
    rsc_type = crm_element_value(rsc->xml, XML_ATTR_TYPE);
    if ((rsc_class == NULL) || (rsc_type == NULL)) {
        CMD_ERR("Resource %s does not have a class and type", rsc_id);
        return EINVAL;
    }

    if (host_uname == NULL) {
        CMD_ERR("Please specify a node name");
        return EINVAL;

    } else {
        pe_node_t *node = pe_find_node(data_set->nodes, host_uname);

        if (node == NULL) {
            CMD_ERR("Node %s not found", host_uname);
            return pcmk_rc_node_unknown;
        }

        if (!(node->details->online)) {
            if (do_fail_resource) {
                CMD_ERR("Node %s is not online", host_uname);
                return ENOTCONN;
            } else {
                cib_only = true;
            }
        }
        if (!cib_only && pe__is_guest_or_remote_node(node)) {
            node = pe__current_node(node->details->remote_rsc);
            if (node == NULL) {
                CMD_ERR("No cluster connection to Pacemaker Remote node %s detected",
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

    return is_set(rsc->flags, pe_rsc_unique)? strdup(name) : clone_strip(name);
}

// \return Standard Pacemaker return code
static int
clear_rsc_history(pcmk_ipc_api_t *controld_api, const char *host_uname,
                  const char *rsc_id, pe_working_set_t *data_set)
{
    int rc = pcmk_ok;

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

static int
clear_rsc_failures(pcmk_ipc_api_t *controld_api, const char *node_name,
                   const char *rsc_id, const char *operation,
                   const char *interval_spec, pe_working_set_t *data_set)
{
    int rc = pcmk_ok;
    const char *failed_value = NULL;
    const char *failed_id = NULL;
    const char *interval_ms_s = NULL;
    GHashTable *rscs = NULL;
    GHashTableIter iter;

    /* Create a hash table to use as a set of resources to clean. This lets us
     * clean each resource only once (per node) regardless of how many failed
     * operations it has.
     */
    rscs = g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, NULL);

    // Normalize interval to milliseconds for comparison to history entry
    if (operation) {
        interval_ms_s = crm_strdup_printf("%u",
                                          crm_parse_interval_spec(interval_spec));
    }

    for (xmlNode *xml_op = __xml_first_child(data_set->failed); xml_op != NULL;
         xml_op = __xml_next(xml_op)) {

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

            if (!fail_rsc || safe_str_neq(rsc_id, fail_rsc->id)) {
                continue;
            }
        }

        // Host name should always have been provided by this point
        failed_value = crm_element_value(xml_op, XML_ATTR_UNAME);
        if (safe_str_neq(node_name, failed_value)) {
            continue;
        }

        // No operation specified means all operations match
        if (operation) {
            failed_value = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
            if (safe_str_neq(operation, failed_value)) {
                continue;
            }

            // Interval (if operation was specified) defaults to 0 (not all)
            failed_value = crm_element_value(xml_op, XML_LRM_ATTR_INTERVAL_MS);
            if (safe_str_neq(interval_ms_s, failed_value)) {
                continue;
            }
        }

        /* not available until glib 2.32
        g_hash_table_add(rscs, (gpointer) failed_id);
        */
        g_hash_table_insert(rscs, (gpointer) failed_id, (gpointer) failed_id);
    }

    g_hash_table_iter_init(&iter, rscs);
    while (g_hash_table_iter_next(&iter, (gpointer *) &failed_id, NULL)) {
        crm_debug("Erasing failures of %s on %s", failed_id, node_name);
        rc = clear_rsc_history(controld_api, node_name, failed_id, data_set);
        if (rc != pcmk_rc_ok) {
            return pcmk_rc2legacy(rc);
        }
    }
    g_hash_table_destroy(rscs);
    return rc;
}

static int
clear_rsc_fail_attrs(pe_resource_t *rsc, const char *operation,
                     const char *interval_spec, pe_node_t *node)
{
    int rc = pcmk_ok;
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

int
cli_resource_delete(pcmk_ipc_api_t *controld_api, const char *host_uname,
                    pe_resource_t *rsc, const char *operation,
                    const char *interval_spec, bool just_failures,
                    pe_working_set_t *data_set)
{
    int rc = pcmk_ok;
    pe_node_t *node = NULL;

    if (rsc == NULL) {
        return -ENXIO;

    } else if (rsc->children) {
        GListPtr lpc = NULL;

        for (lpc = rsc->children; lpc != NULL; lpc = lpc->next) {
            pe_resource_t *child = (pe_resource_t *) lpc->data;

            rc = cli_resource_delete(controld_api, host_uname, child, operation,
                                     interval_spec, just_failures, data_set);
            if (rc != pcmk_ok) {
                return rc;
            }
        }
        return pcmk_ok;

    } else if (host_uname == NULL) {
        GListPtr lpc = NULL;
        GListPtr nodes = g_hash_table_get_values(rsc->known_on);

        if(nodes == NULL && do_force) {
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
                                         just_failures, data_set);
            }
            if (rc != pcmk_ok) {
                g_list_free(nodes);
                return rc;
            }
        }

        g_list_free(nodes);
        return pcmk_ok;
    }

    node = pe_find_node(data_set->nodes, host_uname);

    if (node == NULL) {
        printf("Unable to clean up %s because node %s not found\n",
               rsc->id, host_uname);
        return -ENODEV;
    }

    if (!node->details->rsc_discovery_enabled) {
        printf("Unable to clean up %s because resource discovery disabled on %s\n",
               rsc->id, host_uname);
        return -EOPNOTSUPP;
    }

    if (controld_api == NULL) {
        printf("Dry run: skipping clean-up of %s on %s due to CIB_file\n",
               rsc->id, host_uname);
        return pcmk_ok;
    }

    rc = clear_rsc_fail_attrs(rsc, operation, interval_spec, node);
    if (rc != pcmk_rc_ok) {
        printf("Unable to clean up %s failures on %s: %s\n",
                rsc->id, host_uname, pcmk_rc_str(rc));
        return pcmk_rc2legacy(rc);
    }

    if (just_failures) {
        rc = clear_rsc_failures(controld_api, host_uname, rsc->id, operation,
                                interval_spec, data_set);
    } else {
        rc = clear_rsc_history(controld_api, host_uname, rsc->id, data_set);
        rc = pcmk_rc2legacy(rc);
    }
    if (rc != pcmk_ok) {
        printf("Cleaned %s failures on %s, but unable to clean history: %s\n",
               rsc->id, host_uname, pcmk_strerror(rc));
    } else {
        printf("Cleaned up %s on %s\n", rsc->id, host_uname);
    }
    return rc;
}

int
cli_cleanup_all(pcmk_ipc_api_t *controld_api, const char *node_name,
                const char *operation, const char *interval_spec,
                pe_working_set_t *data_set)
{
    int rc = pcmk_ok;
    int attr_options = pcmk__node_attr_none;
    const char *display_name = node_name? node_name : "all nodes";

    if (controld_api == NULL) {
        printf("Dry run: skipping clean-up of %s due to CIB_file\n",
               display_name);
        return pcmk_ok;
    }

    if (node_name) {
        pe_node_t *node = pe_find_node(data_set->nodes, node_name);

        if (node == NULL) {
            CMD_ERR("Unknown node: %s", node_name);
            return -ENXIO;
        }
        if (pe__is_guest_or_remote_node(node)) {
            attr_options |= pcmk__node_attr_remote;
        }
    }

    rc = pcmk__node_attr_request_clear(NULL, node_name, NULL, operation,
                                       interval_spec, NULL, attr_options);
    if (rc != pcmk_rc_ok) {
        printf("Unable to clean up all failures on %s: %s\n",
                display_name, pcmk_rc_str(rc));
        return pcmk_rc2legacy(rc);
    }

    if (node_name) {
        rc = clear_rsc_failures(controld_api, node_name, NULL,
                                operation, interval_spec, data_set);
        if (rc != pcmk_ok) {
            printf("Cleaned all resource failures on %s, but unable to clean history: %s\n",
                   node_name, pcmk_strerror(rc));
            return rc;
        }
    } else {
        for (GList *iter = data_set->nodes; iter; iter = iter->next) {
            pe_node_t *node = (pe_node_t *) iter->data;

            rc = clear_rsc_failures(controld_api, node->details->uname, NULL,
                                    operation, interval_spec, data_set);
            if (rc != pcmk_ok) {
                printf("Cleaned all resource failures on all nodes, but unable to clean history: %s\n",
                       pcmk_strerror(rc));
                return rc;
            }
        }
    }

    printf("Cleaned up all resources on %s\n", display_name);
    return pcmk_ok;
}

void
cli_resource_check(cib_t * cib_conn, pe_resource_t *rsc)
{
    bool printed = false;
    char *role_s = NULL;
    char *managed = NULL;
    pe_resource_t *parent = uber_parent(rsc);

    find_resource_attr(cib_conn, XML_NVPAIR_ATTR_VALUE, parent->id,
                       NULL, NULL, NULL, XML_RSC_ATTR_MANAGED, &managed);

    find_resource_attr(cib_conn, XML_NVPAIR_ATTR_VALUE, parent->id,
                       NULL, NULL, NULL, XML_RSC_ATTR_TARGET_ROLE, &role_s);

    if(role_s) {
        enum rsc_role_e role = text2role(role_s);

        free(role_s);
        if(role == RSC_ROLE_UNKNOWN) {
            // Treated as if unset

        } else if(role == RSC_ROLE_STOPPED) {
            printf("\n  * Configuration specifies '%s' should remain stopped\n",
                   parent->id);
            printed = true;

        } else if (is_set(parent->flags, pe_rsc_promotable)
                   && (role == RSC_ROLE_SLAVE)) {
            printf("\n  * Configuration specifies '%s' should not be promoted\n",
                   parent->id);
            printed = true;
        }
    }

    if (managed && !crm_is_true(managed)) {
        printf("%s  * Configuration prevents cluster from stopping or starting unmanaged '%s'\n",
               (printed? "" : "\n"), parent->id);
        printed = true;
    }
    free(managed);

    if (rsc->lock_node) {
        printf("%s  * '%s' is locked to node %s due to shutdown\n",
               (printed? "" : "\n"), parent->id, rsc->lock_node->details->uname);
    }

    if (printed) {
        printf("\n");
    }
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
generate_resource_params(pe_resource_t * rsc, pe_working_set_t * data_set)
{
    GHashTable *params = NULL;
    GHashTable *meta = NULL;
    GHashTable *combined = NULL;
    GHashTableIter iter;

    if (!rsc) {
        crm_err("Resource does not exist in config");
        return NULL;
    }

    params = crm_str_table_new();
    meta = crm_str_table_new();
    combined = crm_str_table_new();

    get_rsc_attributes(params, rsc, NULL /* TODO: Pass in local node */ , data_set);
    get_meta_attributes(meta, rsc, NULL /* TODO: Pass in local node */ , data_set);

    if (params) {
        char *key = NULL;
        char *value = NULL;

        g_hash_table_iter_init(&iter, params);
        while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
            g_hash_table_insert(combined, strdup(key), strdup(value));
        }
        g_hash_table_destroy(params);
    }

    if (meta) {
        char *key = NULL;
        char *value = NULL;

        g_hash_table_iter_init(&iter, meta);
        while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
            char *crm_name = crm_meta_name(key);

            g_hash_table_insert(combined, crm_name, strdup(value));
        }
        g_hash_table_destroy(meta);
    }

    return combined;
}

static bool resource_is_running_on(pe_resource_t *rsc, const char *host) 
{
    bool found = TRUE;
    GListPtr hIter = NULL;
    GListPtr hosts = NULL;

    if(rsc == NULL) {
        return FALSE;
    }

    rsc->fns->location(rsc, &hosts, TRUE);
    for (hIter = hosts; host != NULL && hIter != NULL; hIter = hIter->next) {
        pe_node_t *node = (pe_node_t *) hIter->data;

        if(strcmp(host, node->details->uname) == 0) {
            crm_trace("Resource %s is running on %s\n", rsc->id, host);
            goto done;
        } else if(strcmp(host, node->details->id) == 0) {
            crm_trace("Resource %s is running on %s\n", rsc->id, host);
            goto done;
        }
    }

    if(host != NULL) {
        crm_trace("Resource %s is not running on: %s\n", rsc->id, host);
        found = FALSE;

    } else if(host == NULL && hosts == NULL) {
        crm_trace("Resource %s is not running\n", rsc->id);
        found = FALSE;
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

GList*
subtract_lists(GList *from, GList *items, GCompareFunc cmp)
{
    GList *item = NULL;
    GList *result = g_list_copy(from);

    for (item = items; item != NULL; item = item->next) {
        GList *candidate = NULL;
        for (candidate = from; candidate != NULL; candidate = candidate->next) {
            crm_info("Comparing %s with %s", (const char *) candidate->data,
                     (const char *) item->data);
            if(cmp(candidate->data, item->data) == 0) {
                result = g_list_remove(result, candidate->data);
                break;
            }
        }
    }

    return result;
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

static void display_list(GList *items, const char *tag) 
{
    GList *item = NULL;

    for (item = items; item != NULL; item = item->next) {
        fprintf(stdout, "%s%s\n", tag, (const char *)item->data);
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
 * \return pcmk_ok on success, -ENOKEY if unable to upgrade XML
 * \note On success, caller is responsible for freeing memory allocated for
 *       data_set->now.
 * \todo This follows the example of other callers of cli_config_update()
 *       and returns -ENOKEY ("Required key not available") if that fails,
 *       but perhaps -pcmk_err_schema_validation would be better in that case.
 */
int
update_working_set_xml(pe_working_set_t *data_set, xmlNode **xml)
{
    if (cli_config_update(xml, NULL, FALSE) == FALSE) {
        return -ENOKEY;
    }
    data_set->input = *xml;
    data_set->now = crm_time_new(NULL);
    return pcmk_ok;
}

/*!
 * \internal
 * \brief Update a working set's XML input based on a CIB query
 *
 * \param[in] data_set   Data set instance to initialize
 * \param[in] cib        Connection to the CIB manager
 *
 * \return pcmk_ok on success, -errno on failure
 * \note On success, caller is responsible for freeing memory allocated for
 *       data_set->input and data_set->now.
 */
static int
update_working_set_from_cib(pe_working_set_t * data_set, cib_t *cib)
{
    xmlNode *cib_xml_copy = NULL;
    int rc;

    rc = cib->cmds->query(cib, NULL, &cib_xml_copy, cib_scope_local | cib_sync_call);
    if (rc != pcmk_ok) {
        fprintf(stderr, "Could not obtain the current CIB: %s (%d)\n", pcmk_strerror(rc), rc);
        return rc;
    }
    rc = update_working_set_xml(data_set, &cib_xml_copy);
    if (rc != pcmk_ok) {
        fprintf(stderr, "Could not upgrade the current CIB XML\n");
        free_xml(cib_xml_copy);
        return rc;
    }
    return pcmk_ok;
}

static int
update_dataset(cib_t *cib, pe_working_set_t * data_set, bool simulate)
{
    char *pid = NULL;
    char *shadow_file = NULL;
    cib_t *shadow_cib = NULL;
    int rc;

    pe_reset_working_set(data_set);
    rc = update_working_set_from_cib(data_set, cib);
    if (rc != pcmk_ok) {
        return rc;
    }

    if(simulate) {
        pid = pcmk__getpid_s();
        shadow_cib = cib_shadow_new(pid);
        shadow_file = get_shadow_file(pid);

        if (shadow_cib == NULL) {
            fprintf(stderr, "Could not create shadow cib: '%s'\n", pid);
            rc = -ENXIO;
            goto cleanup;
        }

        rc = write_xml_file(data_set->input, shadow_file, FALSE);

        if (rc < 0) {
            fprintf(stderr, "Could not populate shadow cib: %s (%d)\n", pcmk_strerror(rc), rc);
            goto cleanup;
        }

        rc = shadow_cib->cmds->signon(shadow_cib, crm_system_name, cib_command);
        if(rc != pcmk_ok) {
            fprintf(stderr, "Could not connect to shadow cib: %s (%d)\n", pcmk_strerror(rc), rc);
            goto cleanup;
        }

        pcmk__schedule_actions(data_set, data_set->input, NULL);
        run_simulation(data_set, shadow_cib, NULL, TRUE);
        rc = update_dataset(shadow_cib, data_set, FALSE);

    } else {
        cluster_status(data_set);
    }

  cleanup:
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

        max_delay = value? (int) crm_parse_ll(value, NULL) : -1;
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
                                    (resource_is_running_on((r), (h)) == FALSE))

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
 * \return pcmk_ok on success, -errno on failure (exits on certain failures)
 */
int
cli_resource_restart(pe_resource_t *rsc, const char *host, int timeout_ms,
                     cib_t *cib)
{
    int rc = 0;
    int lpc = 0;
    int before = 0;
    int step_timeout_s = 0;
    int sleep_interval = 2;
    int timeout = timeout_ms / 1000;

    bool stop_via_ban = FALSE;
    char *rsc_id = NULL;
    char *orig_target_role = NULL;

    GList *list_delta = NULL;
    GList *target_active = NULL;
    GList *current_active = NULL;
    GList *restart_target_active = NULL;

    pe_working_set_t *data_set = NULL;

    if(resource_is_running_on(rsc, host) == FALSE) {
        const char *id = rsc->clone_name?rsc->clone_name:rsc->id;
        if(host) {
            printf("%s is not running on %s and so cannot be restarted\n", id, host);
        } else {
            printf("%s is not running anywhere and so cannot be restarted\n", id);
        }
        return -ENXIO;
    }

    /* We might set the target-role meta-attribute */
    attr_set_type = XML_TAG_META_SETS;

    rsc_id = strdup(rsc->id);
    if ((pe_rsc_is_clone(rsc) || pe_bundle_replicas(rsc)) && host) {
        stop_via_ban = TRUE;
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
        rc = -ENOMEM;
        goto done;
    }
    set_bit(data_set->flags, pe_flag_no_counts);
    set_bit(data_set->flags, pe_flag_no_compat);
    rc = update_dataset(cib, data_set, FALSE);
    if(rc != pcmk_ok) {
        fprintf(stdout, "Could not get new resource list: %s (%d)\n", pcmk_strerror(rc), rc);
        goto done;
    }

    restart_target_active = get_active_resources(host, data_set->resources);
    current_active = get_active_resources(host, data_set->resources);

    dump_list(current_active, "Origin");

    if (stop_via_ban) {
        /* Stop the clone or bundle instance by banning it from the host */
        BE_QUIET = TRUE;
        rc = cli_resource_ban(rsc_id, host, NULL, cib);

    } else {
        /* Stop the resource by setting target-role to Stopped.
         * Remember any existing target-role so we can restore it later
         * (though it only makes any difference if it's Slave).
         */
        char *lookup_id = clone_strip(rsc->id);

        find_resource_attr(cib, XML_NVPAIR_ATTR_VALUE, lookup_id, NULL, NULL,
                           NULL, XML_RSC_ATTR_TARGET_ROLE, &orig_target_role);
        free(lookup_id);
        rc = cli_resource_update_attribute(rsc, rsc_id, NULL, NULL,
                                           XML_RSC_ATTR_TARGET_ROLE,
                                           RSC_STOPPED, FALSE, cib, data_set);
    }
    if(rc != pcmk_ok) {
        fprintf(stderr, "Could not set target-role for %s: %s (%d)\n", rsc_id, pcmk_strerror(rc), rc);
        if (current_active) {
            g_list_free_full(current_active, free);
        }
        if (restart_target_active) {
            g_list_free_full(restart_target_active, free);
        }
        goto done;
    }

    rc = update_dataset(cib, data_set, TRUE);
    if(rc != pcmk_ok) {
        fprintf(stderr, "Could not determine which resources would be stopped\n");
        goto failure;
    }

    target_active = get_active_resources(host, data_set->resources);
    dump_list(target_active, "Target");

    list_delta = subtract_lists(current_active, target_active, (GCompareFunc) strcmp);
    fprintf(stdout, "Waiting for %d resources to stop:\n", g_list_length(list_delta));
    display_list(list_delta, " * ");

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
            if(rc != pcmk_ok) {
                fprintf(stderr, "Could not determine which resources were stopped\n");
                goto failure;
            }

            if (current_active) {
                g_list_free_full(current_active, free);
            }
            current_active = get_active_resources(host, data_set->resources);
            g_list_free(list_delta);
            list_delta = subtract_lists(current_active, target_active, (GCompareFunc) strcmp);
            dump_list(current_active, "Current");
            dump_list(list_delta, "Delta");
        }

        crm_trace("%d (was %d) resources remaining", g_list_length(list_delta), before);
        if(before == g_list_length(list_delta)) {
            /* aborted during stop phase, print the contents of list_delta */
            fprintf(stderr, "Could not complete shutdown of %s, %d resources remaining\n", rsc_id, g_list_length(list_delta));
            display_list(list_delta, " * ");
            rc = -ETIME;
            goto failure;
        }

    }

    if (stop_via_ban) {
        rc = cli_resource_clear(rsc_id, host, NULL, cib, TRUE);

    } else if (orig_target_role) {
        rc = cli_resource_update_attribute(rsc, rsc_id, NULL, NULL,
                                           XML_RSC_ATTR_TARGET_ROLE,
                                           orig_target_role, FALSE, cib,
                                           data_set);
        free(orig_target_role);
        orig_target_role = NULL;
    } else {
        rc = cli_resource_delete_attribute(rsc, rsc_id, NULL, NULL,
                                           XML_RSC_ATTR_TARGET_ROLE, cib,
                                           data_set);
    }

    if(rc != pcmk_ok) {
        fprintf(stderr, "Could not unset target-role for %s: %s (%d)\n", rsc_id, pcmk_strerror(rc), rc);
        goto done;
    }

    if (target_active) {
        g_list_free_full(target_active, free);
    }
    target_active = restart_target_active;
    list_delta = subtract_lists(target_active, current_active, (GCompareFunc) strcmp);
    fprintf(stdout, "Waiting for %d resources to start again:\n", g_list_length(list_delta));
    display_list(list_delta, " * ");

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

            rc = update_dataset(cib, data_set, FALSE);
            if(rc != pcmk_ok) {
                fprintf(stderr, "Could not determine which resources were started\n");
                goto failure;
            }

            if (current_active) {
                g_list_free_full(current_active, free);
            }

            /* It's OK if dependent resources moved to a different node,
             * so we check active resources on all nodes.
             */
            current_active = get_active_resources(NULL, data_set->resources);
            g_list_free(list_delta);
            list_delta = subtract_lists(target_active, current_active, (GCompareFunc) strcmp);
            dump_list(current_active, "Current");
            dump_list(list_delta, "Delta");
        }

        if(before == g_list_length(list_delta)) {
            /* aborted during start phase, print the contents of list_delta */
            fprintf(stdout, "Could not complete restart of %s, %d resources remaining\n", rsc_id, g_list_length(list_delta));
            display_list(list_delta, " * ");
            rc = -ETIME;
            goto failure;
        }

    }

    rc = pcmk_ok;
    goto done;

  failure:
    if (stop_via_ban) {
        cli_resource_clear(rsc_id, host, NULL, cib, TRUE);
    } else if (orig_target_role) {
        cli_resource_update_attribute(rsc, rsc_id, NULL, NULL,
                                      XML_RSC_ATTR_TARGET_ROLE,
                                      orig_target_role, FALSE, cib, data_set);
        free(orig_target_role);
    } else {
        cli_resource_delete_attribute(rsc, rsc_id, NULL, NULL,
                                      XML_RSC_ATTR_TARGET_ROLE, cib, data_set);
    }

done:
    if (list_delta) {
        g_list_free(list_delta);
    }
    if (current_active) {
        g_list_free_full(current_active, free);
    }
    if (target_active && (target_active != restart_target_active)) {
        g_list_free_full(target_active, free);
    }
    if (restart_target_active) {
        g_list_free_full(restart_target_active, free);
    }
    free(rsc_id);
    pe_free_working_set(data_set);
    return rc;
}

static inline int action_is_pending(pe_action_t *action) 
{
    if(is_set(action->flags, pe_action_optional)) {
        return FALSE;
    } else if(is_set(action->flags, pe_action_runnable) == FALSE) {
        return FALSE;
    } else if(is_set(action->flags, pe_action_pseudo)) {
        return FALSE;
    } else if(safe_str_eq("notify", action->task)) {
        return FALSE;
    }
    return TRUE;
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
actions_are_pending(GListPtr actions)
{
    GListPtr action;

    for (action = actions; action != NULL; action = action->next) {
        pe_action_t *a = (pe_action_t *)action->data;
        if (action_is_pending(a)) {
            crm_notice("Waiting for %s (flags=0x%.8x)", a->uuid, a->flags);
            return TRUE;
        }
    }
    return FALSE;
}

/*!
 * \internal
 * \brief Print pending actions to stderr
 *
 * \param[in] actions   List of actions to check
 *
 * \return void
 */
static void
print_pending_actions(GListPtr actions)
{
    GListPtr action;

    fprintf(stderr, "Pending actions:\n");
    for (action = actions; action != NULL; action = action->next) {
        pe_action_t *a = (pe_action_t *) action->data;

        if (action_is_pending(a)) {
            fprintf(stderr, "\tAction %d: %s", a->id, a->uuid);
            if (a->node) {
                fprintf(stderr, "\ton %s", a->node->details->uname);
            }
            fprintf(stderr, "\n");
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
 * \return pcmk_ok on success, -errno on failure
 */
int
wait_till_stable(int timeout_ms, cib_t * cib)
{
    pe_working_set_t *data_set = NULL;
    int rc = -1;
    int timeout_s = timeout_ms? ((timeout_ms + 999) / 1000) : WAIT_DEFAULT_TIMEOUT_S;
    time_t expire_time = time(NULL) + timeout_s;
    time_t time_diff;
    bool printed_version_warning = BE_QUIET; // i.e. don't print if quiet

    data_set = pe_new_working_set();
    if (data_set == NULL) {
        return -ENOMEM;
    }
    set_bit(data_set->flags, pe_flag_no_counts);
    set_bit(data_set->flags, pe_flag_no_compat);

    do {

        /* Abort if timeout is reached */
        time_diff = expire_time - time(NULL);
        if (time_diff > 0) {
            crm_info("Waiting up to %ld seconds for cluster actions to complete", time_diff);
        } else {
            print_pending_actions(data_set->actions);
            pe_free_working_set(data_set);
            return -ETIME;
        }
        if (rc == pcmk_ok) { /* this avoids sleep on first loop iteration */
            sleep(WAIT_SLEEP_S);
        }

        /* Get latest transition graph */
        pe_reset_working_set(data_set);
        rc = update_working_set_from_cib(data_set, cib);
        if (rc != pcmk_ok) {
            pe_free_working_set(data_set);
            return rc;
        }
        pcmk__schedule_actions(data_set, data_set->input, NULL);

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

            if (safe_str_neq(dc_version, PACEMAKER_VERSION "-" BUILD_VERSION)) {
                printf("warning: wait option may not work properly in "
                       "mixed-version cluster\n");
                printed_version_warning = TRUE;
            }
        }

    } while (actions_are_pending(data_set->actions));

    pe_free_working_set(data_set);
    return pcmk_ok;
}

int
cli_resource_execute_from_params(const char *rsc_name, const char *rsc_class,
                                 const char *rsc_prov, const char *rsc_type,
                                 const char *action, GHashTable *params,
                                 GHashTable *override_hash, int timeout_ms)
{
    GHashTable *params_copy = NULL;
    int rc = pcmk_ok;
    svc_action_t *op = NULL;

    if (safe_str_eq(rsc_class, PCMK_RESOURCE_CLASS_STONITH)) {
        CMD_ERR("Sorry, the %s option doesn't support %s resources yet",
                action, rsc_class);
        crm_exit(CRM_EX_UNIMPLEMENT_FEATURE);
    }

    /* If no timeout was provided, grab the default. */
    if (timeout_ms == 0) {
        timeout_ms = crm_get_msec(CRM_DEFAULT_OP_TIMEOUT_S);
    }

    /* add meta_timeout env needed by some resource agents */
    g_hash_table_insert(params, strdup("CRM_meta_timeout"),
                        crm_strdup_printf("%d", timeout_ms));

    /* add crm_feature_set env needed by some resource agents */
    g_hash_table_insert(params, strdup(XML_ATTR_CRM_VERSION), strdup(CRM_FEATURE_SET));

    /* resources_action_create frees the params hash table it's passed, but we
     * may need to reuse it in a second call to resources_action_create.  Thus
     * we'll make a copy here so that gets freed and the original remains for
     * reuse.
     */
    params_copy = crm_str_table_dup(params);

    op = resources_action_create(rsc_name, rsc_class, rsc_prov, rsc_type, action, 0,
                                 timeout_ms, params_copy, 0);
    if (op == NULL) {
        /* Re-run with stderr enabled so we can display a sane error message */
        crm_enable_stderr(TRUE);
        params_copy = crm_str_table_dup(params);
        op = resources_action_create(rsc_name, rsc_class, rsc_prov, rsc_type, action, 0,
                                     timeout_ms, params_copy, 0);

        /* Callers of cli_resource_execute expect that the params hash table will
         * be freed.  That function uses this one, so for that reason and for
         * making the two act the same, we should free the hash table here too.
         */
        g_hash_table_destroy(params);

        /* We know op will be NULL, but this makes static analysis happy */
        services_action_free(op);
        crm_exit(CRM_EX_DATAERR);
        return rc; // Never reached, but helps static analysis
    }

    setenv("HA_debug", resource_verbose > 0 ? "1" : "0", 1);
    if(resource_verbose > 1) {
        setenv("OCF_TRACE_RA", "1", 1);
    }

    /* A resource agent using the standard ocf-shellfuncs library will not print
     * messages to stderr if it doesn't have a controlling terminal (e.g. if
     * crm_resource is called via script or ssh). This forces it to do so.
     */
    setenv("OCF_TRACE_FILE", "/dev/stderr", 0);

    if (override_hash) {
        GHashTableIter iter;
        char *name = NULL;
        char *value = NULL;

        g_hash_table_iter_init(&iter, override_hash);
        while (g_hash_table_iter_next(&iter, (gpointer *) & name, (gpointer *) & value)) {
            printf("Overriding the cluster configuration for '%s' with '%s' = '%s'\n",
                   rsc_name, name, value);
            g_hash_table_replace(op->params, strdup(name), strdup(value));
        }
    }

    if (services_action_sync(op)) {
        int more, lpc, last;
        char *local_copy = NULL;

        rc = op->rc;

        if (op->status == PCMK_LRM_OP_DONE) {
            printf("Operation %s for %s (%s:%s:%s) returned: '%s' (%d)\n",
                   action, rsc_name, rsc_class, rsc_prov ? rsc_prov : "", rsc_type,
                   services_ocf_exitcode_str(op->rc), op->rc);
        } else {
            printf("Operation %s for %s (%s:%s:%s) failed: '%s' (%d)\n",
                   action, rsc_name, rsc_class, rsc_prov ? rsc_prov : "", rsc_type,
                   services_lrm_status_str(op->status), op->status);
        }

        /* hide output for validate-all if not in verbose */
        if (resource_verbose == 0 && safe_str_eq(action, "validate-all"))
            goto done;

        if (op->stdout_data) {
            local_copy = strdup(op->stdout_data);
            more = strlen(local_copy);
            last = 0;

            for (lpc = 0; lpc < more; lpc++) {
                if (local_copy[lpc] == '\n' || local_copy[lpc] == 0) {
                    local_copy[lpc] = 0;
                    printf(" >  stdout: %s\n", local_copy + last);
                    last = lpc + 1;
                }
            }
            free(local_copy);
        }
        if (op->stderr_data) {
            local_copy = strdup(op->stderr_data);
            more = strlen(local_copy);
            last = 0;

            for (lpc = 0; lpc < more; lpc++) {
                if (local_copy[lpc] == '\n' || local_copy[lpc] == 0) {
                    local_copy[lpc] = 0;
                    printf(" >  stderr: %s\n", local_copy + last);
                    last = lpc + 1;
                }
            }
            free(local_copy);
        }
    } else {
        rc = op->rc == 0 ? pcmk_err_generic : op->rc;
    }

done:
    services_action_free(op);
    /* See comment above about why we free params here. */
    g_hash_table_destroy(params);
    return rc;
}

int
cli_resource_execute(pe_resource_t *rsc, const char *requested_name,
                     const char *rsc_action, GHashTable *override_hash,
                     int timeout_ms, cib_t * cib, pe_working_set_t *data_set)
{
    int rc = pcmk_ok;
    const char *rid = NULL;
    const char *rtype = NULL;
    const char *rprov = NULL;
    const char *rclass = NULL;
    const char *action = NULL;
    GHashTable *params = NULL;

    if (safe_str_eq(rsc_action, "validate")) {
        action = "validate-all";

    } else if (safe_str_eq(rsc_action, "force-check")) {
        action = "monitor";

    } else if (safe_str_eq(rsc_action, "force-stop")) {
        action = rsc_action+6;

    } else if (safe_str_eq(rsc_action, "force-start")
               || safe_str_eq(rsc_action, "force-demote")
               || safe_str_eq(rsc_action, "force-promote")) {
        action = rsc_action+6;

        if(pe_rsc_is_clone(rsc)) {
            rc = cli_resource_search(rsc, requested_name, data_set);
            if(rc > 0 && do_force == FALSE) {
                CMD_ERR("It is not safe to %s %s here: the cluster claims it is already active",
                        action, rsc->id);
                CMD_ERR("Try setting target-role=Stopped first or specifying "
                        "the force option");
                crm_exit(CRM_EX_UNSAFE);
            }
        }

    } else {
        action = rsc_action;
    }

    if(pe_rsc_is_clone(rsc)) {
        /* Grab the first child resource in the hope it's not a group */
        rsc = rsc->children->data;
    }

    if(rsc->variant == pe_group) {
        CMD_ERR("Sorry, the %s option doesn't support group resources",
                rsc_action);
        crm_exit(CRM_EX_UNIMPLEMENT_FEATURE);
    }

    rclass = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    rprov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
    rtype = crm_element_value(rsc->xml, XML_ATTR_TYPE);

    params = generate_resource_params(rsc, data_set);

    if (timeout_ms == 0) {
        timeout_ms = pe_get_configured_timeout(rsc, action, data_set);
    }

    rid = pe_rsc_is_anon_clone(rsc->parent)? requested_name : rsc->id;

    rc = cli_resource_execute_from_params(rid, rclass, rprov, rtype, action,
                                          params, override_hash, timeout_ms);
    return rc;
}

int
cli_resource_move(pe_resource_t *rsc, const char *rsc_id, const char *host_name,
                  cib_t *cib, pe_working_set_t *data_set)
{
    int rc = pcmk_ok;
    unsigned int count = 0;
    pe_node_t *current = NULL;
    pe_node_t *dest = pe_find_node(data_set->nodes, host_name);
    bool cur_is_dest = FALSE;

    if (dest == NULL) {
        return -pcmk_err_node_unknown;
    }

    if (scope_master && is_not_set(rsc->flags, pe_rsc_promotable)) {
        pe_resource_t *p = uber_parent(rsc);

        if (is_set(p->flags, pe_rsc_promotable)) {
            CMD_ERR("Using parent '%s' for move instead of '%s'.", rsc->id, rsc_id);
            rsc_id = p->id;
            rsc = p;

        } else {
            CMD_ERR("Ignoring master option: %s is not promotable", rsc_id);
            scope_master = FALSE;
        }
    }

    current = pe__find_active_requires(rsc, &count);

    if (is_set(rsc->flags, pe_rsc_promotable)) {
        GListPtr iter = NULL;
        unsigned int master_count = 0;
        pe_node_t *master_node = NULL;

        for(iter = rsc->children; iter; iter = iter->next) {
            pe_resource_t *child = (pe_resource_t *)iter->data;
            enum rsc_role_e child_role = child->fns->state(child, TRUE);

            if(child_role == RSC_ROLE_MASTER) {
                rsc = child;
                master_node = pe__current_node(child);
                master_count++;
            }
        }
        if (scope_master || master_count) {
            count = master_count;
            current = master_node;
        }

    }

    if (count > 1) {
        if (pe_rsc_is_clone(rsc)) {
            current = NULL;
        } else {
            return -pcmk_err_multiple;
        }
    }

    if (current && (current->details == dest->details)) {
        cur_is_dest = TRUE;
        if (do_force) {
            crm_info("%s is already %s on %s, reinforcing placement with location constraint.",
                     rsc_id, scope_master?"promoted":"active", dest->details->uname);
        } else {
            return -pcmk_err_already;
        }
    }

    /* Clear any previous prefer constraints across all nodes. */
    cli_resource_clear(rsc_id, NULL, data_set->nodes, cib, FALSE);

    /* Clear any previous ban constraints on 'dest'. */
    cli_resource_clear(rsc_id, dest->details->uname, data_set->nodes, cib, TRUE);

    /* Record an explicit preference for 'dest' */
    rc = cli_resource_prefer(rsc_id, dest->details->uname, cib);

    crm_trace("%s%s now prefers node %s%s",
              rsc->id, scope_master?" (master)":"", dest->details->uname, do_force?"(forced)":"");

    /* only ban the previous location if current location != destination location.
     * it is possible to use -M to enforce a location without regard of where the
     * resource is currently located */
    if(do_force && (cur_is_dest == FALSE)) {
        /* Ban the original location if possible */
        if(current) {
            (void)cli_resource_ban(rsc_id, current->details->uname, NULL, cib);

        } else if(count > 1) {
            CMD_ERR("Resource '%s' is currently %s in %d locations. "
                    "One may now move to %s",
                    rsc_id, (scope_master? "promoted" : "active"),
                    count, dest->details->uname);
            CMD_ERR("To prevent '%s' from being %s at a specific location, "
                    "specify a node.",
                    rsc_id, (scope_master? "promoted" : "active"));

        } else {
            crm_trace("Not banning %s from its current location: not active", rsc_id);
        }
    }

    return rc;
}

static void
cli_resource_why_without_rsc_and_host(cib_t *cib_conn,GListPtr resources)
{
    GListPtr lpc = NULL;
    GListPtr hosts = NULL;

    for (lpc = resources; lpc != NULL; lpc = lpc->next) {
        pe_resource_t *rsc = (pe_resource_t *) lpc->data;
        rsc->fns->location(rsc, &hosts, TRUE);

        if (hosts == NULL) {
            printf("Resource %s is not running\n", rsc->id);
        } else {
            printf("Resource %s is running\n", rsc->id);
        }

        cli_resource_check(cib_conn, rsc);
        g_list_free(hosts);
        hosts = NULL;
     }

}

static void
cli_resource_why_with_rsc_and_host(cib_t *cib_conn, GListPtr resources,
                                   pe_resource_t *rsc, const char *host_uname)
{
    if (resource_is_running_on(rsc, host_uname)) {
        printf("Resource %s is running on host %s\n",rsc->id,host_uname);
    } else {
        printf("Resource %s is not running on host %s\n", rsc->id, host_uname);
    }
    cli_resource_check(cib_conn, rsc);
}

static void
cli_resource_why_without_rsc_with_host(cib_t *cib_conn,GListPtr resources,pe_node_t *node)
{
    const char* host_uname =  node->details->uname;
    GListPtr allResources = node->details->allocated_rsc;
    GListPtr activeResources = node->details->running_rsc;
    GListPtr unactiveResources = subtract_lists(allResources,activeResources,(GCompareFunc) strcmp);
    GListPtr lpc = NULL;

    for (lpc = activeResources; lpc != NULL; lpc = lpc->next) {
        pe_resource_t *rsc = (pe_resource_t *) lpc->data;
        printf("Resource %s is running on host %s\n",rsc->id,host_uname);
        cli_resource_check(cib_conn,rsc);
    }

    for(lpc = unactiveResources; lpc != NULL; lpc = lpc->next) {
        pe_resource_t *rsc = (pe_resource_t *) lpc->data;
        printf("Resource %s is assigned to host %s but not running\n",
               rsc->id, host_uname);
        cli_resource_check(cib_conn,rsc);
     }

     g_list_free(allResources);
     g_list_free(activeResources);
     g_list_free(unactiveResources);
}

static void
cli_resource_why_with_rsc_without_host(cib_t *cib_conn, GListPtr resources,
                                       pe_resource_t *rsc)
{
    GListPtr hosts = NULL;

    rsc->fns->location(rsc, &hosts, TRUE);
    printf("Resource %s is %srunning\n", rsc->id, (hosts? "" : "not "));
    cli_resource_check(cib_conn, rsc);
    g_list_free(hosts);
}

void cli_resource_why(cib_t *cib_conn, GListPtr resources, pe_resource_t *rsc,
                      pe_node_t *node)
{
    const char *host_uname = (node == NULL)? NULL : node->details->uname;

    if ((rsc == NULL) && (host_uname == NULL)) {
        cli_resource_why_without_rsc_and_host(cib_conn, resources);

    } else if ((rsc != NULL) && (host_uname != NULL)) {
        cli_resource_why_with_rsc_and_host(cib_conn, resources, rsc,
                                           host_uname);

    } else if ((rsc == NULL) && (host_uname != NULL)) {
        cli_resource_why_without_rsc_with_host(cib_conn, resources, node);

    } else if ((rsc != NULL) && (host_uname == NULL)) {
        cli_resource_why_with_rsc_without_host(cib_conn, resources, rsc);
    }
}
